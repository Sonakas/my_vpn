#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <iostream>
#include <cstring>
#include <errno.h>

#include <openssl/aes.h>
#include <openssl/rand.h>



AES_KEY encrypt_key, decrypt_key;

void init_keys(const unsigned char* key) {
    AES_set_encrypt_key(key, 256, &encrypt_key);
    AES_set_decrypt_key(key, 256, &decrypt_key);
}

void encrypt_data(const unsigned char* input, unsigned char* output, size_t length) {
    AES_encrypt(input, output, &encrypt_key);
}

void decrypt_data(const unsigned char* input, unsigned char* output, size_t length) {
    AES_decrypt(input, output, &decrypt_key);
}

int create_tun_interface(char *dev) 
{
    struct ifreq ifr;
    int tun_fd = open("/dev/net/tun", O_RDWR );

    if( tun_fd < 0 ) {
        std::cout << ("Error opening /dev/net/tun") << std::endl;
        return -1;
    }

    memset(&ifr, 0 , sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if(ioctl(tun_fd, TUNSETIFF, &ifr) < 0 ) {
        std::cout << "Error creating TUN interface: " <<strerror(errno) << std::endl;
        close(tun_fd);
        return -1;
    }

    std::cout << "Created TUN interface: " << ifr.ifr_name << std::endl;

    return tun_fd;
}

void send_to_server(const unsigned char* data, size_t length) {

    std::cout << "Sending " << length << " bytes to server..." << std::endl;
}

void handle_tun_traffic(int tun_fd) {
    unsigned char buffer[4096];
    while(true) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        if(nread < 0) {
            std::cout << "Error reading from TUN" << std::endl;
            break;
        }

        unsigned char encrypted[4096];
        encrypt_data(buffer, encrypted, nread);

        send_to_server(encrypted, nread);
    }
}

int main() {

    int tun_fd = create_tun_interface("tun%d");
    if(tun_fd < 0) return 1;


    close(tun_fd);

    return 0;
}