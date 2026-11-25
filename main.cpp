//C++ TUN Daemon Program

#include <iostream>
#include <cstring>
#include <linux/if.h>   //Linux NI defs: struct ifreq & IFNAMSIZ constant (16 bytes)
#include <linux/if_tun.h>   //TUN/TAP driver defs: ioctl flags (IFF_TUN, IFF_NO_PI, TUNSETIFF)
#include <fcntl.h>  //(File control) open(), O_RDWR
#include <unistd.h> //POSIX API, read(), write(), open() calls
#include <sys/ioctl.h>  //ioctl() (I/O control)
#include <cstdint>
#include <sys/socket.h> //socket(), bind(), sendto(), AF_INET, SOCK_DGRAM
#include <netinet/in.h> //struct sockaddr_in, htons()
#include <arpa/inet.h>  //inet_pton() (converts ip to binary ip)
#include <sys/epoll.h>  //epoll
#include <thread>   //multithreading

//Allocates or binds to TUN VN device
int tun_alloc(char *dev){    //*dev = interface name (e.g. tun0)
    struct ifreq ifr;   //(interface-request) configures network device params (name, IP, MTU, flags) via ioctl
    int fd; //(File descriptor) returned from /dev/net/tu
    int err;    //Return status of ioctl() system call

    //Open TUN character device
    //Creates new userspace handle to VN when opened
    //O_RDWR means it needs both read (packets from OS) and write (inject into OS)
    //Try to open device
    if ( (fd = open("/dev/net/tun", O_RDWR)) < 0){
        //If failed to open
        perror("Failed to open /dev/net/tun");
        return fd;  //Returns -1 to caller
    }
    
    //(By default OS doesnt clean RAM it gives and may leave leftover junk bits from previous running)
    //Takes starting addr in memory, sets every byte to 0, and covers entire size of struct
    std::memset(&ifr, 0, sizeof(ifr));

    /*
    Configures flags for this VI
    IFF_TUN - configures interface as TUN device
    IFF_NO_PI - (No packet info) by default, TUN adds 4-byte metadata header to every packet read
    */
    //Set interface to TUN and does not attach 4-byte header to each packet
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    //If specific interface name is provided (like tun0)
    if (*dev)
        //Copy requested name into ifr.ifr_name, capped at IFNAMSIZ (16) bytes
        std::strncpy(ifr.ifr_name, dev, IFNAMSIZ);  //IFNAMSIZ = kernel constant usually 16 bytes
    
    //Issue I/O control command to kernel
    //TUNSETIFF tells driver to register NI within ifr and bind it to fd
    //Kernel inspects ifr_name and makes a new dynamic name (tun0, tun1, etc)
    //Reqs CAP_NET_ADMIN (root) privileges
    //&ifr assigns ifr_name with new name that was generated
    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0){
        //If unprivileged user runs program or if interface with that name is already used
        perror("ioctl(TUNSETIFF) failed");
        close(fd);  //Close fd to prevent leak if registration fails
        return err; //Returns -1
    }

    //Copies interface name into dev buffer so they know what it was named
    strcpy(dev, ifr.ifr_name);

    //Return open file descriptor which keeps tun0 alive while open
    //Returns -1 if any system call fails
    return fd;
}

//Standard MTU size + 64B (16B AEAD auth tag, 16B VPN header w/ IV)
static constexpr int buff_max = 1600;

int main(){
    char dev_name[IFNAMSIZ] = "tun%d";   //Creates dynamic tun name

    std::cout << "Allocating TUN device..." << std::endl;

    //Call function to create interface and get descriptor
    int tun_fd = tun_alloc(dev_name);

    //Unix file descriptors: 0 = stdin, 1 = stdout, 2 = stderr, 3+ = files/sockets
    if (tun_fd < 0){
        std::cerr << "Failed to allocate device for non-root/non-CAP_NET_ADMIN" << std::endl;
        return 1;   //non-zero indicating error
    }

    std::cout << "Successfully allocated interface: " << dev_name
              << " (fd: " << tun_fd << ")" << std:: endl;

    //Creates IPv4 (AF_INET) UDP datagram socket
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);    //UDP File Descriptor used to send packets intercepted from kernel

    if (udp_fd < 0){
        perror("Failed to create UDP socket");
        close(tun_fd);
        return 1;
    }

    //Configures local UDP address () 127.0.0.1, 5000, and bind
    struct sockaddr_in local_addr;
    std::memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;    //IPv4
    local_addr.sin_port = htons(5000);  //host->network short to port 5000.
    // ^ (use htons bc cpu stores in little-endian but I require big-endian so htons flips 16-bit port 
    // #'s bytes so kernel puts port 5000 on wire instead of port 34835)
    inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr);  //Convert ip string to bytes

    if (bind(udp_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0){
        perror("Failed to bind");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }

    //Configures remote peer's UDP address 127.0.0.1, 5001
    struct sockaddr_in remote_addr;
    std::memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(5001);
    inet_pton(AF_INET, "127.0.0.1", &remote_addr.sin_addr);

    std::cout << "Waiting for packets..." << std::endl;


    //Buffer to hold incoming raw packets
    uint8_t buffer[buff_max];

    //Main event loop - continuously polls TUN for packets routed to it by kernel
    while (true){

        //read() blocks execution until packet is routed into tun0
        //Kernel then copies arrived packets by raw IP bytes into buffer
        ssize_t bytes_read = read(tun_fd, buffer, sizeof(buffer));

        if (bytes_read < 0){
            //OS-level read error or interrupt occurred
            perror("read() failed");
            break;
        }

        //Shift top 4 bits down to lowest 4
        //0x0F is a bitwise and mask that clears any leftover high bits
        //leaving integer value 4 for IPv4 or 6 for IPv6
        int ip_version = (buffer[0] >> 4) & 0x0F;
        //Just checker for which IP version used and if IFF_NO_PI worked

        if (ip_version == 4 && bytes_read >= 20){
            uint8_t l4_protocol = buffer[9];    //B9 of IPv4 header is layer 4 protocol ID
                //1 = ICMP (ping), 6 = TCP, 17 = UDP
                std::cout << "L4 Protocol ID: " << (int)l4_protocol << std::endl;
        }

        std::cout << "Captured packet: " << bytes_read << " bytes | Ipv" << ip_version << std::endl;

        //Encapsulates in UDP and sends
        //Passing in buffer (raw ip packet) directs kernel to:
        //Take these bytes as payload, wrap in UDP header (5000->5001) & 
        //outer IPv4 header (127.0.0.1->127.0.0.1) and send datagram
                //socket descriptor, data buffer ptr, data length, transmission flags, dest addr struct, addr struct size
        ssize_t bytes_sent = sendto(udp_fd, buffer, bytes_read, 0, 
                                    (struct sockaddr*)&remote_addr, sizeof(remote_addr));

        if (bytes_sent < 0)
            perror("Failed to send packets");
        else
            std::cout << "  -> Encapsulated & sent " << bytes_sent << "B over UDP to " 
            << inet_ntoa(remote_addr.sin_addr) << ":" << ntohs(remote_addr.sin_port) << std::endl;
            //ntoa (network to ascii) ntohs (network to host short)
    }

    close(tun_fd);  //Close fd which causes tun to be torn down and remove any routing
    close (udp_fd);  //Close UDP fd

    return 0;

}