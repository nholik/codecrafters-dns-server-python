import socket
import struct
from dataclasses import dataclass


@dataclass
class DnsMessage:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    def pack(self):
        flags = (
            self.qr << 15
            | self.opcode << 11
            | self.aa << 10
            | self.tc << 9
            | self.rd << 8
            | self.ra << 7
            | self.z << 4
            | self.rcode
        )

        return struct.pack(
            ">HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            resp = DnsMessage(
                id=1234,
                qr=1,
                opcode=0,
                aa=0,
                tc=0,
                rd=0,
                ra=0,
                z=0,
                rcode=0,
                qdcount=0,
                ancount=0,
                nscount=0,
                arcount=0,
            ).pack()

            # response = b""

            udp_socket.sendto(resp, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
