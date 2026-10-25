//Network Device Allocation and sample reading of packets
#include <iostream>
#include <cstring>
#include <linux/if.h>   //Linux NI defs: struct ifreq & IFNAMSIZ constant (16 bytes)
#include <linux/if_tun.h>   //TUN/TAP driver defs: ioctl flags (IFF_TUN, IFF_NO_PI, TUNSETIFF)
#include <fcntl.h>  //(File control) open(), O_RDWR
#include <unistd.h> //POSIX API, read(), write(), open() calls
#include <sys/ioctl.h>  //ioctl() (I/O control)
#include <cstdint>

//Allocates or binds to TUN VN device
int tun_alloc(char *dev){    //*dev = interface name (e.g. tun0)
    struct ifreq ifr;   //(interface-request) configures network device params (name, IP, MTU, flags) via ioctl
    int fd; //(File descriptor) returned from /dev/net/tun
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
    std::cout << "Waiting for packets..." << std::endl;

    //Buffer to hold incoming raw packets
    uint8_t buffer[1500];   //1500 bytes for MTU 

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

        std::cout << "Captured packet: " << bytes_read << " bytes | Ipv" << ip_version << std::endl;
    }

    close(tun_fd);  //Close fd which causes tun to be torn down and remove any routing

    return 0;

}