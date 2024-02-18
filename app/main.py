import socket
import struct
from dataclasses import dataclass


@dataclass
class DnsAnswer:
    name: bytes
    type: int
    cls: int
    ttl: int
    data: str

    def pack(self):
        # packed_name = b"\x0ccodecrafters\x02io\x00"
        type_bytes = (1).to_bytes(2, byteorder="big")
        class_bytes = (1).to_bytes(2, byteorder="big")
        ttl_bytes = (self.ttl).to_bytes(4, byteorder="big")
        length_bytes = (4).to_bytes(2, byteorder="big")
        data_bytes = struct.pack("!BBBB", 8, 8, 8, 8)

        return (
            self.name + type_bytes + class_bytes + ttl_bytes + length_bytes + data_bytes
        )


class DnsQuestion:
    __type: bytes
    __cls: bytes
    __next_offset: int
    __packed_names: bytes
    __input_data: bytes

    @property
    def packed(self):
        return self.__packed_names + self.__type + self.__cls

    @property
    def names(self):
        return self.__packed_names

    @property
    def next_question(self):
        return self.__next_offset

    @property
    def has_next_question(self):
        return self.__next_offset < len(self.__input_data) - 5

    @property
    def is_compressed(self):
        return (self.__input_data[0] & 0xC0) == 0xC0

    def __init__(self, question_data):
        self.__input_data = question_data
        self.__type = (1).to_bytes(2, byteorder="big")
        self.__cls = (1).to_bytes(2, byteorder="big")

        self.__packed_names = b""
        question_offset = 0

        question_len = int.from_bytes(question_data[0:1], byteorder="big")

        while question_len > 0:
            name = struct.unpack(
                "c" * question_len,
                question_data[question_offset + 1 : question_offset + question_len + 1],
            )
            self.__packed_names += len(name).to_bytes(1, byteorder="big")
            for c in name:
                self.__packed_names += c
            question_offset += question_len + 1

            question_len = int.from_bytes(
                question_data[question_offset : question_offset + 1],
                byteorder="big",
            )

        self.__packed_names += b"\x00"
        self.__next_offset = question_offset

    def __repr__(self):
        return f"Names: {self.__packed_names}, Compressed: {self.is_compressed}, Has Next Question: {self.has_next_question}"


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
            req_header = struct.unpack(">H", buf[2:4])
            op_code = (req_header[0] >> 11) & 15

            resp_header = DnsResponseHeader(
                id=int.from_bytes(buf[0:2], byteorder="big"),
                qr=1,
                opcode=op_code,
                aa=0,
                tc=0,
                rd=(req_header[0] & 256 != 0),
                ra=0,
                z=0,
                rcode=(0 if op_code == 0 else 4),
                qdcount=1,
                ancount=1,
                nscount=0,
                arcount=0,
            ).pack()

            print(f"original buff: {buf}")
            all_questions = []
            question = DnsQuestion(buf[12:])
            all_questions.append(question)
            print(question)
            while question.has_next_question:
                print(question)
                print(buf[12+question.next_question:])
                question = DnsQuestion(buf[12 + question.next_question :])
                all_questions.append(question)
                print(question)

            resp_answer = DnsAnswer(
                name=all_questions[0].names, type=1, cls=1, ttl=60, data="8.8.8.8"
            ).pack()

            resp = resp_header + question.packed + resp_answer

            udp_socket.sendto(resp, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
