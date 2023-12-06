from network import Protocol, StreamSocket, Socket
from random import randint
from queue import Queue, Empty
from threading import Timer
from collections import namedtuple

# Reserved protocol number for experiments; see RFC 3692
IPPROTO_RDT = 0xfe
EPHEMERAL_PORT_MIN = 49152
TIMEOUT = 0.001
MAX_TRIES = 5000
DEBUG = False

MsgFlags = namedtuple("MsgFlags", "ACK RST SYN FIN", defaults=[ 0, 0, 0, 0 ])
PacketInfo = namedtuple("PacketInfo", "srcp destp seqnum acknum flags rwnd checksum payload length", defaults=[ 0, 0, 0, 0, MsgFlags(), 0, 0, b'', 0 ])

class ConnectionState :
    NOT_CONNECTED, LISTENING, WAIT_SYN_ACK, CONNECTED, WAIT_FIN = range(5)

def calc_checksum(segment) :
    return sum([ int.from_bytes(segment[i:i+2], byteorder="big") for i in range(0, len(segment), 2) ]) & 0xFFFF

def encode_hdr(pinfo, calcsum=True):
    segment = (
            pinfo.srcp.to_bytes(2, byteorder="big") 
          + pinfo.destp.to_bytes(2, byteorder="big") 
          + pinfo.seqnum.to_bytes(4, byteorder="big") 
          + pinfo.acknum.to_bytes(4, byteorder="big") 
          + flags_bytes(pinfo.flags) 
          + pinfo.rwnd.to_bytes(2, byteorder="big") )
    return segment + (calc_checksum(segment + pinfo.payload) if calcsum else pinfo.checksum).to_bytes(2, byteorder="big") + pinfo.payload

def decode_hdr(seg) :
    return PacketInfo(
            srcp=int.from_bytes(seg[:2], byteorder="big"), 
            destp=int.from_bytes(seg[2:4], byteorder="big"), 
            seqnum=int.from_bytes(seg[4:8], byteorder="big"), 
            acknum=int.from_bytes(seg[8:12], byteorder="big"), 
            flags=flags_tuple(seg[12:14]), 
            rwnd=int.from_bytes(seg[14:16], byteorder="big"), 
            checksum=int.from_bytes(seg[16:18], byteorder="big"),
            payload=seg[18:],
            length=len(seg))

# Returns a tuple of the 4 flags as integers (which may be interpreted as booleans) from a single flags bytes object.
def flags_tuple(flags) :
    return MsgFlags(*[(int.from_bytes(flags, byteorder="big") >> i) & 1 for i in range(4)])

# Returns a bytes object representing the four values from their representation as integers.
def flags_bytes(flags) :
    return (flags.ACK | (flags.RST << 1) | (flags.SYN << 2) | (flags.FIN << 3)).to_bytes(2, byteorder="big")

# Returns the sequence number for the next packet after this one. This must never be 0.
def next_seqnum(seqnum, length) :
    return ((seqnum + length) % 0xFFFFFFFF) + 1
  
class RDTSocket(StreamSocket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Integer in [0, 65535) representing the port of this socket.
        # If this is None, it means that bind() has not been called.
        self.port = None
        # Tuple representing the (addr, port) of the remote address.
        # If this is None, it means either the socket is a server listening socket or connect() has not been called
        self.rhost = None
        self.connection_state = ConnectionState.NOT_CONNECTED
        self.seqnum = randint(1, 0x100000000)
        self.acknum = 0
        # Set of incoming connections, used to avoid duplicate SYN packets
        self.incoming_conns_set = set()
        # Queue of incoming connections. Contents will be of the form ((rhost, srcp), seqnum)
        self.incoming_conns = Queue()
        # Queue to block until ACK is received. Contents will be the acknum of the incoming packet
        self.incoming_acks = Queue(1)
        # Timer after transmission of final ACK message, before connection reset
        self.reset_timer = None

    def is_connected(self) :
        return self.connection_state in (ConnectionState.WAIT_SYN_ACK, ConnectionState.CONNECTED)

    def check_state(self, aiu=False, ac=False, nc=False, nb=False, al=False, nl=False, port=None):
        if aiu and self.proto.sockets.get(port) and self.proto.sockets[port].get(self.rhost) :
            raise Socket.AddressInUse
        if ac and self.is_connected() : 
            raise StreamSocket.AlreadyConnected
        if nc and not self.is_connected() :
            raise StreamSocket.NotConnected
        if nb and not self.port :
            raise StreamSocket.NotBound
        if al and self.connection_state == ConnectionState.LISTENING :
            raise StreamSocket.AlreadyListening
        if nl and self.connection_state != ConnectionState.LISTENING :
            raise StreamSocket.NotListening

    def bind(self, port) :
        self.check_state(aiu=True, ac=True, port=port)
        self.port = port
        if self.proto.sockets.get(port) :
            self.proto.sockets[port].update({ self.rhost: self })
        else :
            self.proto.sockets.update( { port: { self.rhost: self } } )

    def listen(self) : 
        self.check_state(nb=True, ac=True)
        self.connection_state = ConnectionState.LISTENING

    def accept(self) :
        self.check_state(nl=True)
        socket = RDTSocket(self.proto)
        socket.rhost, ackn = self.incoming_conns.get()
        self.incoming_conns_set.remove(socket.rhost)
        socket.bind(self.port)
        socket.connection_state = ConnectionState.CONNECTED
        if DEBUG : print("Accepting connection; sending SYN ACK #" + str(socket.seqnum))
        socket.send_block_until_ack(PacketInfo(srcp=self.port, destp=socket.rhost[1], seqnum=socket.seqnum, acknum=ackn, flags=MsgFlags(SYN=1, ACK=1)), socket.rhost[0])
        return (socket, socket.rhost)

    def connect(self, addr) :
        self.check_state(al=True, ac=True)
        if not self.port :
            self.bind(self.proto.get_unused_ephemeral_port())
        self.proto.sockets[self.port].update({ addr: self })
        self.connection_state = ConnectionState.WAIT_SYN_ACK
        self.rhost = addr
        self.send_block_until_ack(PacketInfo(srcp=self.port, destp=addr[1], seqnum=self.seqnum, flags=MsgFlags(SYN=1)), addr[0])

    def send(self, data) :
        self.check_state(nc=True)
        self.send_block_until_ack(PacketInfo(srcp=self.port, destp=self.rhost[1], seqnum=self.seqnum, flags=MsgFlags(), payload=data), self.rhost[0])

    def close(self) :
        self.check_state(nc=True)
        self.connection_state = ConnectionState.WAIT_FIN
        self.send_block_until_ack(PacketInfo(srcp=self.port, destp=int(self.rhost[1]), seqnum=self.seqnum, flags=MsgFlags(FIN=1)), self.rhost[0])

    def ack(self, ackn, seqn=0, check_conn=True) :
        self.check_state(nc=check_conn)
        self.output(encode_hdr(PacketInfo(srcp=self.port, destp=int(self.rhost[1]), seqnum=seqn, acknum=ackn, flags=MsgFlags(ACK=1))), self.rhost[0])

    def send_block_until_ack(self, pinfo, addr, fin=False) :
        seg = encode_hdr(pinfo)
        self.seqnum = next_seqnum(pinfo.seqnum, len(seg))
        sim_close = False
        rem_tries = MAX_TRIES
        while True :
            if DEBUG : print("Transmitting packet #" + str(pinfo.seqnum) + " with flags " + str(pinfo.flags))
            self.output(seg, addr)
            if (rem_tries := rem_tries - 1) == 0 :
                self.proto.reset_conn(self, mode='timeout')
            try :
                while (a := self.incoming_acks.get(timeout=TIMEOUT)).acknum != self.seqnum :
                    if DEBUG : print("Popped duplicate ACK from queue; ignoring")
                    if a.flags.FIN and pinfo.flags.FIN : sim_close = True
                if DEBUG : print("self.wait_for_ack released for packet #" + str(pinfo.seqnum) + "!")
                break
            except Empty :
                continue
        if sim_close :
            self.set_reset_timer(Timer(0.1, self.proto.reset_conn, args=[ self ], kwargs={ 'mode': 'graceful' }), pinfo)
        if fin :
            self.proto.reset_conn(self, mode='graceful')

    def handle_input(self, pinfo) :
        match self.connection_state :
            case ConnectionState.WAIT_SYN_ACK :
                if pinfo.flags.SYN and pinfo.flags.ACK :
                    self.acknum = next_seqnum(pinfo.seqnum, pinfo.length) 
                    self.connection_state = ConnectionState.CONNECTED
                    self.ack(self.acknum, seqn=self.seqnum)
            case ConnectionState.CONNECTED :
                if pinfo.flags.FIN :
                    if DEBUG : print("received FIN packet #" + str(pinfo.seqnum) + " on server")
                    self.set_reset_timer(Timer(0.01, self.send_block_until_ack, args=[ PacketInfo(srcp=self.port, destp=int(self.rhost[1]), seqnum=self.seqnum, flags=MsgFlags(FIN=1)), self.rhost[0] ], kwargs={ 'fin': True }), pinfo)
                if pinfo.flags.SYN and pinfo.flags.ACK :
                    self.ack(next_seqnum(pinfo.seqnum, pinfo.length), seqn=self.seqnum)
                if (pinfo.flags.ACK and not pinfo.flags.SYN) and pinfo.seqnum :
                    self.acknum = pinfo.seqnum
                if not pinfo.flags.ACK and not pinfo.flags.SYN and not pinfo.flags.FIN: 
                    if pinfo.seqnum == self.acknum : 
                        if pinfo.payload : self.deliver(pinfo.payload)
                        self.acknum = next_seqnum(pinfo.seqnum, pinfo.length)
                    self.ack(next_seqnum(pinfo.seqnum, pinfo.length))
            case ConnectionState.WAIT_FIN :
                if pinfo.flags.FIN :
                    if DEBUG : print("received FIN packet #" + str(pinfo.seqnum) + " on client")
                    self.set_reset_timer(Timer(0.1, self.proto.reset_conn, args=[ self ], kwargs={ 'mode': 'graceful' }), pinfo)

    def set_reset_timer(self, timer, pinfo) :
        if self.reset_timer :
            self.reset_timer.cancel()
        self.reset_timer = timer 
        self.ack(next_seqnum(pinfo.seqnum, pinfo.length), check_conn=False)
        self.reset_timer.start()

    class ConnectionReset(Exception) :
        """The connection was forcefully reset by the remote host."""

    class ConnectionTimeout(Exception) :
        """The connection exceeded its timeout limit due to an unresponsive remote host."""

class RDTProtocol(Protocol):
    PROTO_ID = IPPROTO_RDT
    SOCKET_CLS = RDTSocket

    def __init__(self, *args, **kwargs) :
        super().__init__(*args, **kwargs)
        # A dict of dicts; reference is self.sockets[port][rhost]
        self.sockets = {}

    def input(self, seg, rhost) :
        pinfo = decode_hdr(seg)
        if (c := calc_checksum(encode_hdr(pinfo._replace(checksum=0), calcsum=False))) != pinfo.checksum :
            if DEBUG : print("Errors detected on packet " + str(pinfo.seqnum) + "! Flags: " + str(pinfo.flags))
            return

        ss = self.sockets.get(pinfo.destp)
        if ss and (sock := ss.get( (rhost, pinfo.srcp) )) :
            if pinfo.flags.RST :
                self.reset_conn(sock)
            if ((pinfo.flags.ACK and pinfo.acknum == sock.seqnum) or pinfo.flags.RST or pinfo.flags.FIN) and sock.incoming_acks.empty() :
                if DEBUG and pinfo.flags.ACK : print("Got ACK #" + str(pinfo.acknum) + "; releasing lock")
                # Release the lock on the waiting socket. If this is an ACK packet, allows the socket to continue sending; if it is an RST packet, allows the socket to handle a connection reset.
                sock.incoming_acks.put(pinfo, block=False)
            sock.handle_input(pinfo)
        elif ss and ss.get(None) and ss[None].connection_state == ConnectionState.LISTENING and pinfo.flags.SYN :
            if DEBUG : print("Received SYN packet #" + str(pinfo.seqnum) + " on listening socket")
            # This is a port listening on incoming connections; put this in the socket's queue if it is not already there
            if not (rhost, pinfo.srcp) in ss[None].incoming_conns_set :
                if DEBUG : print("Adding " + str( (rhost, pinfo.srcp) ) + " to incoming_conns_set " + str(ss[None].incoming_conns_set))
                ss[None].incoming_conns_set.add( (rhost, pinfo.srcp) )
                ss[None].incoming_conns.put( ((rhost, pinfo.srcp), next_seqnum(pinfo.seqnum, pinfo.length)) )
        elif pinfo.flags.SYN :
            if DEBUG : print("Received SYN packet #" + str(pinfo.seqnum) + " on a port without a listening socket; sending RST packet")
            # This port is closed; send a packet with the RST flag set.
            RDTSocket(self).output(encode_hdr(PacketInfo(srcp=pinfo.destp, destp=pinfo.srcp, flags=MsgFlags(RST=1))), rhost)

    def reset_conn(self, socket, mode='reset') :
        if sock := self.sockets[socket.port].get(socket.rhost) :
            sock.connection_state = ConnectionState.NOT_CONNECTED
            del self.sockets[socket.port][socket.rhost]
        match mode :
            case 'reset' :
                raise RDTSocket.ConnectionReset("Connection Reset")
            case 'graceful' :
                pass
            case 'timeout' :
                raise RDTSocket.ConnectionTimeout("Connection Timed Out")
            case _ :
                print("WARNING! Unknown connection reset mode " + mode)

    def get_unused_ephemeral_port(self) :
        while self.sockets.get(i := randint(EPHEMERAL_PORT_MIN, 65535)) :
            pass
        return i
