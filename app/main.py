import socket
import struct
from dataclasses import dataclass
from typing import List


@dataclass
class DnsAnswer:
    name: str
    type: int
    cls: int
    ttl: int
    data: str

    def pack(self):
        packed_name = self.name.encode() + b"\x00"
        type_bytes = (1).to_bytes(2, byteorder="big")
        class_bytes = (1).to_bytes(2, byteorder="big")
        ttl_bytes = (self.ttl).to_bytes(4, byteorder="big")
        length_bytes = (len(self.name)).to_bytes(4, byteorder="big")
        data_bytes = b"\x08\x08\x08\x08"

        return (
            packed_name
            + type_bytes
            + class_bytes
            + ttl_bytes
            + length_bytes
            + data_bytes
        )


@dataclass
class DnsQuestion:
    names: List[str]
    type: int
    cls: int

    def pack(self):
        packed_names = b""
        for n in self.names:
            name_ln = len(n)
            packed_names += name_ln.to_bytes(1, byteorder="big")
            packed_names += n.encode()

        packed_names += b"\x00"

        type_bytes = (1).to_bytes(2, byteorder="big")
        cls_bytes = (1).to_bytes(2, byteorder="big")

        return packed_names + type_bytes + cls_bytes


@dataclass
class DnsResponseHeader:
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
            resp_header = DnsResponseHeader(
                id=1234,
                qr=1,
                opcode=0,
                aa=0,
                tc=0,
                rd=0,
                ra=0,
                z=0,
                rcode=0,
                qdcount=1,
                ancount=1,
                nscount=0,
                arcount=0,
            ).pack()

            resp_question = DnsQuestion(["codecrafters", "io"], 1, 1).pack()
            resp_answer = DnsAnswer(
                name="codecrafters.io", type=1, cls=1, ttl=300, data="8.8.8.8"
            ).pack()
            print(resp_answer)

            resp = resp_header + resp_question + resp_answer

            udp_socket.sendto(resp, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
