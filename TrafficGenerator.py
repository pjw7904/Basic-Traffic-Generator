'''
    A basic traffic generator to determine:
        1. packets received.
        2. packets received out of order.
        3. packets missing.
        4. packets that are duplicates.

    A custom test protocol header is placed in the payload of ICMP packets, resulting in frames containing:
        [Ethernet II / IPv4 / ICMP / test protocol]

    The test protocol header used in the this traffic generator is as follows:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Source Physical Address               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Sequence Number                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Padding                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Where padding is added until the frame is 1400 bytes in length.

    Author: Peter Willis (pjw7904@rit.edu)
'''

from scapy.all import *
from subprocess import call
from pathlib import Path
import time
import argparse
import sys
import os

frameCounter = {}  # Global dictionary to hold frame/packet payload content for analysis on the receiving end

DEFAULT_PCAP_SENTINEL = "__DEFAULT_PCAP__"


def scriptDir() -> Path:
    """Directory containing this script (not the current working directory)."""
    return Path(__file__).resolve().parent


def defaultPcapPath() -> Path:
    """Default capture path when -r/--receive or -a/--analyze is used without a filename."""
    # Always use /tmp to avoid SELinux/home labeling issues on some FABRIC images.
    return Path("/tmp") / "results.pcap"


def resolvePcapArg(arg_val):
    """
    Unify -r/-a behavior:

    - If arg_val is DEFAULT_PCAP_SENTINEL => use defaultPcapPath()
    - If arg_val is a real string => use it
    """
    if arg_val == DEFAULT_PCAP_SENTINEL:
        return str(defaultPcapPath())
    return arg_val


def ensureCaptureFile(path_str: str):
    """
    Ensure the capture file exists and is chmod 777.
    Also tries to chown back to the invoking sudo user if possible.
    Returns an absolute path string for tshark.

    Note: This intentionally allows overwriting existing captures.
    """
    p = Path(path_str).expanduser()

    # Make sure parent exists
    p_parent = p.parent
    if p_parent and not p_parent.exists():
        p_parent.mkdir(parents=True, exist_ok=True)

    # Touch file (ok if it already exists)
    try:
        p.touch(exist_ok=True)
    except Exception as e:
        sys.exit(f"Failed to create capture file '{p}': {e}")

    # chmod 777
    try:
        os.chmod(p, 0o777)
    except Exception as e:
        sys.exit(f"Failed to chmod 777 on '{p}': {e}")

    # If running via sudo, try to set ownership back to original user
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            import grp
            uid = pwd.getpwnam(sudo_user).pw_uid
            gid = grp.getgrnam(sudo_user).gr_gid
            os.chown(p, uid, gid)
        except Exception:
            # Non-fatal; permissions are already wide open
            pass

    return str(p.resolve())


def main():
    argParser = argparse.ArgumentParser(
        description="Basic traffic generator for protocol reconvergence testing purposes"
    )

    # Sender arguments.
    argParser.add_argument("-s", "--send")                 # Destination (receiver) node
    argParser.add_argument("-c", "--count", type=int)      # The number of frames to send.
    argParser.add_argument("-d", "--delay", type=float)    # Add a delay when sending traffic.

    # Receiver arguments.
    # -r with no value => /tmp/results.pcap
    argParser.add_argument(
        "-r", "--receive",
        nargs="?",
        const=DEFAULT_PCAP_SENTINEL,
        default=None,
        help="Receive traffic and write to a pcap file (default: /tmp/results.pcap)"
    )

    # Analyzer arguments.
    # -a with no value => /tmp/results.pcap
    argParser.add_argument(
        "-a", "--analyze",
        nargs="?",
        const=DEFAULT_PCAP_SENTINEL,
        default=None,
        help="Analyze a capture file (default: /tmp/results.pcap)"
    )

    # Shared arguments.
    argParser.add_argument("-e", "--port", default="eth1")  # By default, it's eth1 on our testbeds.

    args = argParser.parse_args()
    port = args.port

    # Receive traffic.
    if args.receive is not None:
        capture_arg = resolvePcapArg(args.receive)
        capture_path = ensureCaptureFile(capture_arg)
        recvTraffic(port, capture_path)

    # Send traffic.
    elif args.send:
        dstLogicalAddr = args.send
        count = args.count
        delay = args.delay
        sendTraffic(dstLogicalAddr, count, delay, port)

    # Analyze traffic.
    elif args.analyze is not None:
        captureFile = resolvePcapArg(args.analyze)
        print(f"Working on capture file {captureFile}...")
        analyzeTraffic(captureFile)

    else:
        sys.exit("Syntax error: incorrect arguments (use -h for help)")

    return None


def sendTraffic(dstLogicalAddr, count, delay, port):
    srcPhysicalAddr = get_if_hwaddr(port)

    PDUToSend = Ether(src=srcPhysicalAddr) / IP(dst=dstLogicalAddr) / ICMP(type=1)
    generateContinousTraffic(PDUToSend, count, srcPhysicalAddr, delay, port)

    return None


def generateContinousTraffic(PDUToSend, numberOfFramesToSend, srcPhysicalAddr, delay, port):
    PAYLOAD_DELIMITER_SIZE = 2
    MAX_PAYLOAD_LENGTH = 1400

    sequenceNumber = 0
    payloadPadding = 0
    complete = False if numberOfFramesToSend is not None else True

    while not complete:
        try:
            sequenceNumber += 1

            frameLength = len(str(sequenceNumber) + srcPhysicalAddr) + len(PDUToSend) + PAYLOAD_DELIMITER_SIZE
            if frameLength < MAX_PAYLOAD_LENGTH:
                payloadPadding = MAX_PAYLOAD_LENGTH - frameLength
            else:
                payloadPadding = 0

            frameWithCustomPayload = PDUToSend / Raw(
                load="{0}|{1}|{2}".format(srcPhysicalAddr, sequenceNumber, 'A' * payloadPadding)
            )

            sendp(frameWithCustomPayload, iface=port, count=1, verbose=False)

            sys.stdout.write(f"\rSent {sequenceNumber} frames")
            sys.stdout.flush()

            if sequenceNumber == numberOfFramesToSend:
                complete = True
                print("\nFinished")

            if delay is not None:
                time.sleep(delay)

        except KeyboardInterrupt:
            complete = True
            print("Finished")

    return None


def recvTraffic(port, captureFilePath):
    srcPhysicalAddr = get_if_hwaddr(port)

    # BPF capture filter: exclude our own source MAC and only match ICMP type 1
    capture_filter = f"ether src not {srcPhysicalAddr} and icmp[0] == 1"

    command = [
        "sudo", "tshark",
        "-i", str(port),
        "-w", str(captureFilePath),
        "-F", "libpcap",
        capture_filter,
    ]

    try:
        call(command)
    except KeyboardInterrupt:
        print("\nExited program")

    return None


def analyzeTraffic(capturePath):
    frameCounter = {}

    pcap_path = Path(capturePath).expanduser().resolve()
    if not pcap_path.exists():
        sys.exit(f"Capture file does not exist: {pcap_path}")

    capture = rdpcap(str(pcap_path))

    for frame in capture:
        if not (frame.haslayer(ICMP) and frame[ICMP].type == 1 and frame.haslayer(Raw)):
            continue

        payload = frame[Raw].load
        payload = str(payload, 'utf-8', errors='replace')
        payloadContent = payload.split("|")

        if len(payloadContent) < 2:
            continue

        source = payloadContent[0]
        try:
            newSeqNum = int(payloadContent[1])
        except ValueError:
            continue

        if source not in frameCounter:
            frameCounter[source] = [newSeqNum, [], 1, [], []]
        else:
            currentSeqNum = frameCounter[source][0]
            expectedNextSeqNum = currentSeqNum + 1

            if currentSeqNum == newSeqNum and newSeqNum == 1:
                continue

            if newSeqNum in frameCounter[source][1]:
                frameCounter[source][1].remove(newSeqNum)
                frameCounter[source][3].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            if newSeqNum not in frameCounter[source][1] and (newSeqNum < currentSeqNum or newSeqNum == currentSeqNum):
                frameCounter[source][4].append(newSeqNum)
                frameCounter[source][2] += 1
                continue

            missedFrames = newSeqNum - expectedNextSeqNum
            while missedFrames != 0:
                missingSeqNum = currentSeqNum + missedFrames
                frameCounter[source][1].append(missingSeqNum)
                missedFrames -= 1

            frameCounter[source][0] = newSeqNum
            frameCounter[source][2] += 1

    # Write the results file to the same directory as the python script.
    out_dir = scriptDir()
    out_dir.mkdir(parents=True, exist_ok=True)

    resultFile = out_dir / f"{pcap_path.stem}_result.txt"
    with open(resultFile, "w+") as f:
        for source in frameCounter:
            endStatement = "{0} frames lost from source {1} {2} | {3} received | {4} Not sequential {5} | {6} duplicates {7}\n"
            outputMissingFrames = ""
            outputUnorderedFrames = ""
            outputDuplicateFrames = ""

            if frameCounter[source][1]:
                frameCounter[source][1].sort()
                outputMissingFrames = frameCounter[source][1]

            if frameCounter[source][3]:
                frameCounter[source][3].sort()
                outputUnorderedFrames = frameCounter[source][3]

            if frameCounter[source][4]:
                frameCounter[source][4].sort()
                outputDuplicateFrames = frameCounter[source][4]

            f.write(endStatement.format(
                len(frameCounter[source][1]),
                source,
                outputMissingFrames,
                frameCounter[source][2],
                len(frameCounter[source][3]),
                outputUnorderedFrames,
                len(frameCounter[source][4]),
                outputDuplicateFrames
            ))

    print(f"Wrote results to: {resultFile}")
    return None


if __name__ == "__main__":
    main()