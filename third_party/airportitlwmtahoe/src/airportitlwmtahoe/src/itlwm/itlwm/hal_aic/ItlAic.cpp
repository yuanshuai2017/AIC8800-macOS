/*
 * AIC8800D80 (USB, fullmac) backend for AirportItlwm-Tahoe. GPL-2.0.
 *
 * How a fullmac chip sits under net80211 (a softmac stack):
 *  - scan: SCANU_START_REQ; every SCANU_RESULT_IND carries a raw beacon/probe-resp that is fed to
 *    ieee80211_input(), so net80211 builds its node table; SCANU_START_CFM -> ieee80211_end_scan().
 *  - join: net80211 runs SCAN->AUTH->ASSOC->RUN as usual. On AUTH we send SM_CONNECT_REQ; the auth
 *    and assoc request frames net80211 queues are dropped in if_start. When the firmware reports
 *    SM_CONNECT_IND we inject a synthetic auth response and an assoc response built from the real
 *    response IEs, so net80211's own code moves the node to RUN and arms the WPA2 supplicant.
 *  - WPA2: EAPOL frames travel as data; net80211 does the 4-way handshake and calls ic_set_key,
 *    which becomes MM_KEY_ADD_REQ. The control port opens once the group key is in.
 *  - data: RX frames are raw 802.11 (hardware-decrypted, CCMP header kept) -> RXI_HWDEC, and
 *    net80211 does the PN replay check. TX frames are Ethernet frames wrapped in a 28-byte hostdesc.
 *
 * Threading: net80211 runs on the main workloop. Two kernel threads block on the bulk-IN pipes;
 * they complete command confirmations directly (a sender may hold the gate) and queue everything
 * else for the workloop through an IOInterruptEventSource.
 */
#include "ItlAic.hpp"
#include "AICInitSeq.h"
#include <kern/thread.h>
#include <libkern/OSAtomic.h>
#include <net80211/ieee80211_proto.h>

// Defined in ieee80211_input.c but not exported by a header; used for the RX reorder window.
void ieee80211_input_ba_gap_timeout(void *arg);
void ieee80211_ba_move_window(struct ieee80211com *, struct ieee80211_node *, u_int8_t, u_int16_t,
                              struct mbuf_list *);

#undef super                            // also compiled inside IOPCIEDeviceWrapper.cpp
#define super ItlHalService
OSDefineMetaClassAndStructors(ItlAic, ItlHalService)

#define AICLOG(fmt, ...) IOLog("AIC8800: " fmt "\n", ##__VA_ARGS__)

// endpoints (interface 2, descriptor order)
static const uint8_t kEpDataOut = 0x01, kEpDataIn = 0x81, kEpCmdOut = 0x02, kEpCmdIn = 0x82;
static const uint32_t kCmdBufSize = 4096;
static const uint32_t kDataRxSize = 32768;   // firmware aggregates up to 20 KiB per transfer
static const uint32_t kDataTxSize = 4096;
static const uint32_t kRxHdrLen = 60;        // hw_rxhdr in front of every received 802.11 frame
static const uint32_t kRxQueueMax = 1024;

// lmac message ids (AIC8800-macOS/tools/hdr/msg_names.txt)
enum : uint16_t {
    MM_ADD_IF_REQ = 0x0006, MM_ADD_IF_CFM = 0x0007, MM_REMOVE_IF_REQ = 0x0008, MM_REMOVE_IF_CFM = 0x0009,
    MM_KEY_ADD_REQ = 0x0024, MM_KEY_ADD_CFM = 0x0025, MM_KEY_DEL_REQ = 0x0026, MM_KEY_DEL_CFM = 0x0027,
    MM_GET_MAC_ADDR_REQ = 0x0073, MM_GET_FW_VERSION_REQ = 0x0080,
    SCANU_START_REQ = 0x1000, SCANU_START_CFM = 0x1001, SCANU_RESULT_IND = 0x1004,
    SCANU_START_CFM_ADDTIONAL = 0x1009,
    ME_SET_CONTROL_PORT_REQ = 0x1404, ME_SET_CONTROL_PORT_CFM = 0x1405,
    SM_CONNECT_REQ = 0x1800, SM_CONNECT_CFM = 0x1801, SM_CONNECT_IND = 0x1802,
    SM_DISCONNECT_REQ = 0x1803, SM_DISCONNECT_CFM = 0x1804, SM_DISCONNECT_IND = 0x1805,
};
static const uint16_t DRV_TASK_ID = 100;
enum : uint8_t { MAC_CIPHER_WEP40 = 0, MAC_CIPHER_TKIP = 1, MAC_CIPHER_CCMP = 2, MAC_CIPHER_WEP104 = 3 };
enum : uint32_t { CONTROL_PORT_HOST = 1u << 0, WPA_WPA2_IN_USE = 1u << 3 };
enum : uint8_t { USB_TYPE_CFG = 0x10, USB_TYPE_CFG_CMD_RSP = 0x11 };

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

#pragma mark - transport

bool ItlAic::openPipes()
{
    // Call into IOUSBHostFamily without fPipeLock held (an unplug may be waiting on it), publish after.
    IOUSBHostPipe *cmdOut = fIntf->copyPipe(kEpCmdOut), *cmdIn = fIntf->copyPipe(kEpCmdIn);
    IOUSBHostPipe *dataOut = fIntf->copyPipe(kEpDataOut), *dataIn = fIntf->copyPipe(kEpDataIn);
    IOLockLock(fPipeLock);
    fCmdOut = cmdOut;
    fCmdIn = cmdIn;
    fDataOut = dataOut;
    fDataIn = dataIn;
    IOLockUnlock(fPipeLock);
    fCmdTxBuf = fIntf->createIOBuffer(kIODirectionOut, kCmdBufSize);
    fCmdRxBuf = fIntf->createIOBuffer(kIODirectionIn, kCmdBufSize);
    fDataTxBuf = fIntf->createIOBuffer(kIODirectionOut, kDataTxSize);
    fDataRxBuf = fIntf->createIOBuffer(kIODirectionIn, kDataRxSize);
    return fCmdOut && fCmdIn && fDataOut && fDataIn && fCmdTxBuf && fCmdRxBuf && fDataTxBuf && fDataRxBuf;
}

// Pipe pointers are only released under fPipeLock, so this is safe from any thread (unplug, bring-up).
void ItlAic::abortPipes()
{
    if (!fPipeLock)
        return;
    IOLockLock(fPipeLock);
    IOUSBHostPipe *pipes[] = {fCmdIn, fDataIn, fCmdOut, fDataOut};
    for (IOUSBHostPipe *p : pipes)
        if (p)
            p->abort(IOUSBHostIOSource::kAbortSynchronous, kIOReturnAborted, nullptr);
    IOLockUnlock(fPipeLock);
}

void ItlAic::abortTransport()
{
    OSIncrementAtomic(&fStopping);
    abortPipes();
    if (fCfmLock) {                         // a command sender must not sit out its full timeout
        IOLockLock(fCfmLock);
        IOLockWakeup(fCfmLock, &fWaitDone, false);
        IOLockUnlock(fCfmLock);
    }
}

void ItlAic::closePipes()
{
    OSIncrementAtomic(&fStopping);
    abortPipes();
    for (int i = 0; i < 200 && fThreads; i++)
        IOSleep(10);
    if (fThreads) {
        // A reader is still inside io(): releasing its pipe or buffer would be a use-after-free. Leak instead.
        AICLOG("reader threads still running at close, keeping pipes");
        return;
    }
    if (fPipeLock)
        IOLockLock(fPipeLock);
    OSSafeReleaseNULL(fCmdOut); OSSafeReleaseNULL(fCmdIn);
    OSSafeReleaseNULL(fDataOut); OSSafeReleaseNULL(fDataIn);
    OSSafeReleaseNULL(fCmdTxBuf); OSSafeReleaseNULL(fCmdRxBuf);
    OSSafeReleaseNULL(fDataTxBuf); OSSafeReleaseNULL(fDataRxBuf);
    if (fPipeLock)
        IOLockUnlock(fPipeLock);
}

void ItlAic::shutdownTransport()
{
    closePipes();
    fTransportUp = false;
}

struct AicThreadArg { ItlAic *self; bool dataPipe; };

void ItlAic::rxThreadEntry(void *arg, wait_result_t)
{
    AicThreadArg a = *(AicThreadArg *)arg;
    IOFree(arg, sizeof(AicThreadArg));
    a.self->rxLoop(a.dataPipe);
    OSDecrementAtomic(&a.self->fThreads);
    thread_terminate(current_thread());
}

void ItlAic::rxLoop(bool dataPipe)
{
    IOUSBHostPipe *pipe = dataPipe ? fDataIn : fCmdIn;
    IOBufferMemoryDescriptor *buf = dataPipe ? fDataRxBuf : fCmdRxBuf;
    uint32_t size = dataPipe ? kDataRxSize : kCmdBufSize;
    int errors = 0;
    while (!fStopping) {
        uint32_t got = 0;
        IOReturn r = pipe->io(buf, size, got, 0);
        if (fStopping)
            break;
        if (r == kIOReturnAborted || r == kIOReturnNoDevice || r == kIOReturnNotResponding ||
            r == kIOReturnOffline || r == kIOReturnNotAttached) {
            AICLOG("%s pipe stopped (0x%x)", dataPipe ? "data" : "cmd", r);
            break;
        }
        if (r != kIOReturnSuccess) {
            if (++errors > 50) {
                AICLOG("%s pipe: too many errors (last 0x%x)", dataPipe ? "data" : "cmd", r);
                break;
            }
            pipe->clearStall(true);
            IOSleep(10);
            continue;
        }
        errors = 0;
        parseTransfer((const uint8_t *)buf->getBytesNoCopy(), got);
    }
}

// Reader-thread context. Several frames can share one transfer.
void ItlAic::parseTransfer(const uint8_t *b, uint32_t len)
{
    uint32_t off = 0;
    while (off + 4 <= len) {
        const uint8_t *e = b + off;
        uint8_t type = e[2];
        if (!(type & USB_TYPE_CFG)) {       // data: u16 frame length, 60-byte rx header, frame
            uint32_t total = rd16(e) + kRxHdrLen;
            if (rd16(e) == 0 || off + total > len)
                break;
            queueRx(0, e, total);
            off += total;
            continue;
        }
        uint32_t plen = rd16(e) & 0x0fff;   // config: 4-byte header, then plen bytes, 4-byte aligned
        if (plen == 0 || off + 4 + plen > len)
            break;
        const uint8_t *body = e + 4;
        if ((type & 0x7f) == USB_TYPE_CFG_CMD_RSP && plen >= 12) {
            uint16_t id = rd16(body);
            uint32_t mlen = rd16(body + 6);
            if (12 + mlen > plen)
                mlen = plen - 12;
            const uint8_t *param = body + 12;
            bool consumed = false;
            IOLockLock(fCfmLock);
            if (fWaitId && id == fWaitId && !fWaitDone) {
                fCfmLen = (uint16_t)MIN(mlen, (uint32_t)sizeof(fCfm));
                memcpy(fCfm, param, fCfmLen);
                fWaitDone = true;
                consumed = true;
                IOLockWakeup(fCfmLock, &fWaitDone, false);
            }
            IOLockUnlock(fCfmLock);
            if (!consumed)
                queueRx(id, param, mlen);
        }
        // 0x12 (TX confirm) and 0x13 (firmware print) are ignored.
        off += 4 + ((plen + 3) & ~3u);
    }
}

void ItlAic::queueRx(uint16_t msgId, const uint8_t *data, uint32_t len)
{
    IOInterruptEventSource *src = fRxSource;
    if (!src)                               // bring-up: not attached to the workloop yet, nothing to deliver to
        return;
    AicRxPkt *pkt = (AicRxPkt *)IOMalloc(sizeof(AicRxPkt) + len);
    if (!pkt)
        return;
    pkt->next = nullptr;
    pkt->len = len;
    pkt->msgId = msgId;
    memcpy(pkt->data, data, len);
    IOLockLock(fCfmLock);
    if (fRxCount >= kRxQueueMax) {
        IOLockUnlock(fCfmLock);
        IOFree(pkt, sizeof(AicRxPkt) + len);
        return;
    }
    if (fRxTail)
        fRxTail->next = pkt;
    else
        fRxHead = pkt;
    fRxTail = pkt;
    fRxCount++;
    IOLockUnlock(fCfmLock);
    src->interruptOccurred(nullptr, nullptr, 0);
}

// Workloop context.
void ItlAic::rxSourceAction(OSObject *owner, IOInterruptEventSource *, int)
{
    ItlAic *that = (ItlAic *)owner;
    for (;;) {
        IOLockLock(that->fCfmLock);
        AicRxPkt *pkt = that->fRxHead;
        that->fRxHead = that->fRxTail = nullptr;
        that->fRxCount = 0;
        IOLockUnlock(that->fCfmLock);
        if (!pkt)
            break;
        while (pkt) {
            AicRxPkt *next = pkt->next;
            if (that->com.sc_newstate) {    // set once the ic is attached
                if (pkt->msgId)
                    that->handleMsg(pkt->msgId, pkt->data, pkt->len);
                else
                    that->handleData(pkt->data, pkt->len);
            }
            IOFree(pkt, sizeof(AicRxPkt) + pkt->len);
            pkt = next;
        }
    }
}

bool ItlAic::usbWrite(IOUSBHostPipe *pipe, IOBufferMemoryDescriptor *buf, uint32_t len)
{
    uint32_t done = 0;
    IOReturn r = pipe->io(buf, len, done, 2000);
    if (r != kIOReturnSuccess || done != len) {
        AICLOG("usb write failed 0x%x (%u/%u)", r, done, len);
        return false;
    }
    if ((len & 511) == 0)                   // high-speed bulk: end the transfer with a ZLP
        pipe->io(buf, (uint32_t)0, done, 1000);
    return true;
}

int ItlAic::waitCfm(uint16_t cfmId, void *cfmOut, uint16_t cfmMax, uint32_t timeoutMs)
{
    uint64_t deadline;
    clock_interval_to_deadline(timeoutMs, kMillisecondScale, &deadline);
    IOLockLock(fCfmLock);
    while (!fWaitDone && !fStopping) {     // abortTransport() wakes us on unplug
        if (IOLockSleepDeadline(fCfmLock, &fWaitDone, deadline, THREAD_UNINT) == THREAD_TIMED_OUT)
            break;
    }
    bool ok = fWaitDone;
    if (ok && cfmOut)
        memcpy(cfmOut, fCfm, MIN(cfmMax, fCfmLen));
    fWaitId = 0;
    IOLockUnlock(fCfmLock);
    if (!ok)
        AICLOG("timeout waiting for cfm 0x%04x", cfmId);
    return ok ? 0 : ETIMEDOUT;
}

int ItlAic::sendRawFrame(const uint8_t *frame, uint32_t len, uint16_t cfmId,
                         void *cfmOut, uint16_t cfmMax, uint32_t timeoutMs)
{
    if (len > kCmdBufSize || !fCmdOut || fStopping)
        return EIO;
    IOLockLock(fCmdLock);
    memcpy(fCmdTxBuf->getBytesNoCopy(), frame, len);
    IOLockLock(fCfmLock);
    fWaitId = cfmId;
    fWaitDone = false;
    IOLockUnlock(fCfmLock);
    int err = usbWrite(fCmdOut, fCmdTxBuf, len) ? 0 : EIO;
    if (!err && cfmId)
        err = waitCfm(cfmId, cfmOut, cfmMax, timeoutMs);
    IOLockLock(fCfmLock);
    fWaitId = 0;
    IOLockUnlock(fCfmLock);
    IOLockUnlock(fCmdLock);
    return err;
}

// Frame: u16 (len+4)&0xfff, u8 0x11, u8 0, u32 0, then lmac_msg {id, dest task, src task, param_len}.
int ItlAic::sendMsg(uint16_t id, const void *param, uint16_t plen, uint16_t cfmId,
                    void *cfmOut, uint16_t cfmMax, uint32_t timeoutMs)
{
    uint8_t f[16 + 400];
    if (plen > sizeof(f) - 16)
        return EINVAL;
    memset(f, 0, 16);
    wr16(f, (uint16_t)((8 + plen + 4) & 0x0fff));
    f[2] = USB_TYPE_CFG_CMD_RSP;
    wr16(f + 8, id);
    wr16(f + 10, id >> 10);                 // destination task is encoded in the id
    wr16(f + 12, DRV_TASK_ID);
    wr16(f + 14, plen);
    if (plen)
        memcpy(f + 16, param, plen);
    return sendRawFrame(f, 16 + plen, cfmId, cfmOut, cfmMax, timeoutMs);
}

#pragma mark - bring-up

int ItlAic::addVif(const uint8_t *mac)
{
    uint8_t req[10] = {};                   // mm_add_if_req: type 0 (STA), mac @2, p2p @8
    memcpy(req + 2, mac, 6);
    uint8_t cfm[2] = {1, 0};                // status, inst_nbr
    int err = sendMsg(MM_ADD_IF_REQ, req, sizeof(req), MM_ADD_IF_CFM, cfm, sizeof(cfm));
    if (err || cfm[0]) {
        AICLOG("MM_ADD_IF failed (err %d status %u)", err, cfm[0]);
        return err ? err : EIO;
    }
    fVifIdx = cfm[1];
    memcpy(fVifMac, mac, 6);
    return 0;
}

// Replays the captured Linux init (DBG_MEM_READ .. MM_SET_COEX), then adds the STA vif with the
// efuse MAC. Frame 14 (SCANU_VENDOR_IE) is replayed too; frame 15 (the captured scan) is not.
bool ItlAic::firmwareInit()
{
    uint8_t cfm[64];
    uint8_t mac[6] = {};
    for (uint32_t i = 0; i < kAICInitSeqCount; i++) {
        const AICInitFrame &f = kAICInitSeq[i];
        if (f.id == MM_ADD_IF_REQ) {
            if (addVif(mac))
                return false;
            continue;
        }
        if (f.id == SCANU_START_REQ)
            continue;
        memset(cfm, 0, sizeof(cfm));
        int err = sendRawFrame(f.data, f.len, (uint16_t)(f.id + 1), cfm, sizeof(cfm), 3000);
        if (err) {
            AICLOG("init frame %u (id 0x%04x) failed: %d", i, f.id, err);
            return false;
        }
        if (f.id == MM_GET_FW_VERSION_REQ) {
            uint32_t n = MIN((uint32_t)cfm[0], (uint32_t)sizeof(fFwVersion) - 1);
            n = MIN(n, (uint32_t)sizeof(cfm) - 1);
            memcpy(fFwVersion, cfm + 1, n);
            fFwVersion[n] = 0;
        } else if (f.id == MM_GET_MAC_ADDR_REQ) {
            memcpy(mac, cfm, 6);
        }
    }
    AICLOG("firmware %s, mac %02x:%02x:%02x:%02x:%02x:%02x, vif %u", fFwVersion,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], fVifIdx);
    return true;
}

void ItlAic::setupIC()
{
    struct ieee80211com *ic = &com.sc_ic;
    struct _ifnet *ifp = &ic->ic_if;

    ic->ic_phytype = IEEE80211_T_OFDM;
    ic->ic_opmode = IEEE80211_M_STA;
    ic->ic_state = IEEE80211_S_INIT;
    ic->ic_caps = IEEE80211_C_RSN | IEEE80211_C_SCANALL | IEEE80211_C_SCANALLBAND |
        IEEE80211_C_SHSLOT | IEEE80211_C_SHPREAMBLE;
    ic->ic_sup_rates[IEEE80211_MODE_11A] = ieee80211_std_rateset_11a;
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;

    for (int i = 1; i <= 13; i++) {
        ic->ic_channels[i].ic_freq = ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
        ic->ic_channels[i].ic_flags = IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
            IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
    }
    static const uint8_t ch5[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124,
                                  128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
    for (uint8_t c : ch5) {
        ic->ic_channels[c].ic_freq = ieee80211_ieee2mhz(c, IEEE80211_CHAN_5GHZ);
        ic->ic_channels[c].ic_flags = IEEE80211_CHAN_A;
    }
    ic->ic_ibss_chan = &ic->ic_channels[1];
    ic->ic_max_rssi = 100;                  // rxi_rssi = dBm + 100, as WCL expects (IWM_MIN_DBM)
    IEEE80211_ADDR_COPY(ic->ic_myaddr, fVifMac);

    ifp->if_softc = &com;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST | IFF_DEBUG;
    ifp->if_ioctl = aic_ioctl;
    ifp->if_start = aic_start;
    ifp->if_watchdog = aic_watchdog;
    strlcpy(ifp->if_xname, "aic0", sizeof(ifp->if_xname));

    ieee80211_ifattach(ifp, getController());
    ic->ic_set_key = aic_set_key;
    ic->ic_delete_key = aic_delete_key;
    com.sc_newstate = ic->ic_newstate;
    ic->ic_newstate = aic_newstate;
    ieee80211_media_init(ifp);
}

// AicUSBDeviceWrapper's bring-up thread, never the IOKit matching thread: firmwareInit() is ~15
// command round trips with a 3 s timeout each, and used to run inside AirportItlwm::start().
bool ItlAic::bringUp()
{
    fPipeLock = IOLockAlloc();
    fCmdLock = IOLockAlloc();
    fCfmLock = IOLockAlloc();
    if (!fIntf || !fPipeLock || !fCmdLock || !fCfmLock || !openPipes()) {
        AICLOG("bring-up: no interface, lock or pipe");
        shutdownTransport();
        return false;
    }
    for (int i = 0; i < 2; i++) {
        AicThreadArg *a = (AicThreadArg *)IOMalloc(sizeof(AicThreadArg));
        thread_t th;
        if (!a)
            break;
        a->self = this;
        a->dataPipe = i == 1;
        OSIncrementAtomic(&fThreads);
        if (kernel_thread_start(rxThreadEntry, a, &th) != KERN_SUCCESS) {
            OSDecrementAtomic(&fThreads);
            IOFree(a, sizeof(AicThreadArg));
            break;
        }
        thread_deallocate(th);
    }
    if (fThreads != 2 || fStopping || !firmwareInit()) {
        AICLOG("bring-up failed%s", fStopping ? " (device going away)" : "");
        shutdownTransport();
        return false;
    }
    fTransportUp = true;
    return true;
}

// AirportItlwm::start(), after initWithController(): the firmware is already up (bringUp()).
bool ItlAic::attach(IOPCIDevice *)
{
    if (!fTransportUp || fStopping) {
        AICLOG("attach: transport not up");
        return false;
    }
    IOInterruptEventSource *src = IOInterruptEventSource::interruptEventSource(this, rxSourceAction);
    if (!src || getMainWorkLoop()->addEventSource(src) != kIOReturnSuccess) {
        OSSafeReleaseNULL(src);
        return false;
    }
    src->enable();
    fRxSource = src;                        // publish last: reader threads start delivering now
    setupIC();
    return true;
}

void ItlAic::drainRxQueue()
{
    if (!fCfmLock)
        return;
    IOLockLock(fCfmLock);
    AicRxPkt *pkt = fRxHead;
    fRxHead = fRxTail = nullptr;
    fRxCount = 0;
    IOLockUnlock(fCfmLock);
    while (pkt) {
        AicRxPkt *next = pkt->next;
        IOFree(pkt, sizeof(AicRxPkt) + pkt->len);
        pkt = next;
    }
}

void ItlAic::detach(IOPCIDevice *)
{
    // Raise fStopping inside the gate: no workloop action is mid-transfer once this returns.
    // Free the reorder buffers inside the gate too: their gap timers run on the workloop.
    getMainCommandGate()->runAction([](OSObject *, void *a, void *, void *, void *) -> IOReturn {
        ItlAic *that = static_cast<ItlAic *>(a);
        OSIncrementAtomic(&that->fStopping);
        if (that->com.sc_newstate)
            that->rxBaStopAll(false);
        return kIOReturnSuccess;
    }, this);
    shutdownTransport();
    if (IOInterruptEventSource *src = fRxSource) {
        fRxSource = nullptr;
        src->disable();
        getMainWorkLoop()->removeEventSource(src);
        if (!fThreads)                      // a stuck reader may still hold the pointer: leak rather than UAF
            src->release();
    }
    if (com.sc_newstate) {
        ieee80211_ifdetach(&com.sc_ic.ic_if);
        com.sc_newstate = nullptr;
    }
    drainRxQueue();
    if (fPendingEapol) {
        mbuf_freem(fPendingEapol);
        fPendingEapol = nullptr;
    }
}

void ItlAic::free()
{
    drainRxQueue();
    if (fPipeLock) {
        IOLockFree(fPipeLock);
        fPipeLock = nullptr;
    }
    if (fCmdLock) {
        IOLockFree(fCmdLock);
        fCmdLock = nullptr;
    }
    if (fCfmLock) {
        IOLockFree(fCfmLock);
        fCfmLock = nullptr;
    }
    super::free();
}

#pragma mark - interface lifecycle

IOReturn ItlAic::enable(IONetworkInterface *)
{
    struct _ifnet *ifp = &com.sc_ic.ic_if;
    if (ifp->if_flags & IFF_UP)
        return kIOReturnSuccess;
    ifp->if_flags |= IFF_UP;
    return aicInit(ifp) ? kIOReturnError : kIOReturnSuccess;
}

IOReturn ItlAic::disable(IONetworkInterface *)
{
    struct _ifnet *ifp = &com.sc_ic.ic_if;
    if (!(ifp->if_flags & IFF_UP))
        return kIOReturnSuccess;
    ifp->if_flags &= ~IFF_UP;
    if (ifp->if_flags & IFF_RUNNING)
        aicStop(ifp);
    return kIOReturnSuccess;
}

int ItlAic::aicInit(struct _ifnet *ifp)
{
    struct ieee80211com *ic = &com.sc_ic;
    if (ic->ic_event_handler)
        ic->ic_event_handler(ic, IEEE80211_EVT_DRIVER_RESET_BEGIN, NULL);
    // WCL rotates the MAC (private Wi-Fi address) through setHardwareAddress(), which only
    // updates the ifnet; pick it up like iwx does and recreate the vif with it.
    const uint8_t *lladdr = ((struct arpcom *)ifp)->ac_enaddr;
    if (!IEEE80211_ADDR_EQ(lladdr, etheranyaddr))
        IEEE80211_ADDR_COPY(ic->ic_myaddr, lladdr);
    if (!IEEE80211_ADDR_EQ(ic->ic_myaddr, fVifMac)) {
        AICLOG("vif mac -> %s", ether_sprintf(ic->ic_myaddr));
        sendMsg(MM_REMOVE_IF_REQ, &fVifIdx, 1, MM_REMOVE_IF_CFM);
        if (addVif(ic->ic_myaddr)) {
            ifp->if_flags &= ~IFF_UP;
            return EIO;
        }
    }
    ifq_clr_oactive(&ifp->if_snd);
    ifp->if_flags |= IFF_RUNNING;
    ieee80211_begin_scan(ifp);
    if (ic->ic_event_handler)
        ic->ic_event_handler(ic, IEEE80211_EVT_DRIVER_READY, NULL);
    return 0;
}

void ItlAic::aicStop(struct _ifnet *ifp)
{
    struct ieee80211com *ic = &com.sc_ic;
    ifp->if_timer = 0;
    ifp->if_flags &= ~IFF_RUNNING;
    // A scan the firmware still runs completes into a non-SCAN state and is ignored.
    ic->ic_flags &= ~(IEEE80211_F_BGSCAN | IEEE80211_F_ASCAN);
    ic->ic_wcl_scan_requested = false;
    ic->ic_wcl_scan_active = false;
    ic->ic_wcl_scan_ssid_length = 0;
    if (ic->ic_event_handler)
        ic->ic_event_handler(ic, IEEE80211_EVT_DRIVER_STOPPED, NULL);
    ifq_clr_oactive(&ifp->if_snd);
    ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
    fwDisconnect();
}

int ItlAic::aic_ioctl(struct _ifnet *ifp, u_long cmd, caddr_t data)
{
    ItlAic *that = fromIC((struct ieee80211com *)ifp);
    int error = 0;

    switch (cmd) {
    case SIOCSIFADDR:
        ifp->if_flags |= IFF_UP;
        /* FALLTHROUGH */
    case SIOCSIFFLAGS:
        if (ifp->if_flags & IFF_UP) {
            if (!(ifp->if_flags & IFF_RUNNING))
                error = that->aicInit(ifp);
        } else if (ifp->if_flags & IFF_RUNNING) {
            that->aicStop(ifp);
        }
        break;
    default:
        error = ieee80211_ioctl(ifp, cmd, data);
    }
    if (error == ENETRESET) {
        error = 0;
        if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)) {
            that->aicStop(ifp);
            error = that->aicInit(ifp);
        }
    }
    return error;
}

#pragma mark - net80211 state machine

int ItlAic::startScan()
{
    struct ieee80211com *ic = &com.sc_ic;
    uint8_t req[376] = {};                  // scanu_start_req
    uint32_t n = 0;
    for (int c = 1; c <= IEEE80211_CHAN_MAX && n < 42; c++) {
        struct ieee80211_channel *ch = &ic->ic_channels[c];
        if (!ch->ic_flags)
            continue;
        uint8_t *d = req + n * 6;           // mac_chan_def: freq, band, flags, tx_power
        wr16(d, ch->ic_freq);
        d[2] = IEEE80211_IS_CHAN_5GHZ(ch) ? 1 : 0;
        d[4] = 20;
        n++;
    }
    // ssid[0] is the wildcard; a directed probe for WCL's or the join SSID finds hidden networks.
    uint8_t nssid = 1;
    const uint8_t *dssid = nullptr;
    uint8_t dlen = 0;
    if (ic->ic_wcl_scan_ssid_length) {
        dssid = ic->ic_wcl_scan_ssid;
        dlen = ic->ic_wcl_scan_ssid_length;
    } else if (ic->ic_des_esslen) {
        dssid = ic->ic_des_essid;
        dlen = ic->ic_des_esslen;
    }
    if (dssid && dlen <= 32) {
        req[252 + 33] = dlen;
        memcpy(req + 252 + 33 + 1, dssid, dlen);
        nssid = 2;
    }
    memset(req + 352, 0xff, 6);             // bssid
    req[366] = fVifIdx;
    req[367] = (uint8_t)n;
    req[368] = nssid;
    int err = sendMsg(SCANU_START_REQ, req, sizeof(req), SCANU_START_CFM_ADDTIONAL, nullptr, 0, 1000);
    fScanning = err == 0;
    if (err)
        AICLOG("scan start failed: %d", err);
    return err;
}

int ItlAic::startConnect(struct ieee80211_node *ni)
{
    struct ieee80211com *ic = &com.sc_ic;
    uint8_t req[320] = {};                  // sm_connect_req
    req[0] = (uint8_t)MIN((int)ni->ni_esslen, 32);
    memcpy(req + 1, ni->ni_essid, req[0]);
    memcpy(req + 34, ni->ni_bssid, 6);
    wr16(req + 40, ni->ni_chan->ic_freq);
    req[42] = IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) ? 1 : 0;
    uint32_t flags = 0;
    uint8_t *ie = req + 64, *end = ie;
    if (ic->ic_flags & IEEE80211_F_RSNON) {
        flags = CONTROL_PORT_HOST | WPA_WPA2_IN_USE;
        if (ni->ni_rsnprotos & IEEE80211_PROTO_RSN)
            end = ieee80211_add_rsn(end, ic, ni);
        else if (ni->ni_rsnprotos & IEEE80211_PROTO_WPA)
            end = ieee80211_add_wpa(end, ic, ni);
    }
    wr32(req + 48, flags);
    req[52] = 0x88; req[53] = 0x8e;         // control port ethertype, network order
    wr16(req + 54, (uint16_t)(end - ie));
    req[60] = 1;                            // uapsd_queues, as the Linux driver sends
    req[61] = fVifIdx;

    uint8_t cfm[1] = {1};
    int err = sendMsg(SM_CONNECT_REQ, req, sizeof(req), SM_CONNECT_CFM, cfm, sizeof(cfm), 3000);
    if (err || cfm[0]) {
        AICLOG("SM_CONNECT_REQ failed (err %d status %u)", err, cfm[0]);
        return err ? err : EIO;
    }
    fConnecting = true;
    AICLOG("connecting to %s on %u MHz", ether_sprintf(ni->ni_bssid), ni->ni_chan->ic_freq);
    return 0;
}

void ItlAic::fwDisconnect()
{
    rxBaStopAll(false);
    if (fPendingEapol) {
        mbuf_freem(fPendingEapol);
        fPendingEapol = nullptr;
    }
    if (!fFwConnected && !fConnecting)
        return;
    fFwConnected = fConnecting = false;
    fPortOpen = false;
    uint8_t req[4] = {};                    // sm_disconnect_req: reason, vif_idx
    wr16(req, IEEE80211_REASON_AUTH_LEAVE);
    req[2] = fVifIdx;
    sendMsg(SM_DISCONNECT_REQ, req, sizeof(req), SM_DISCONNECT_CFM);
    deleteHwKeys();
}

void ItlAic::deleteHwKeys()
{
    int *slots[] = {&fHwKeyPairwise, &fHwKeyGroup[0], &fHwKeyGroup[1], &fHwKeyGroup[2], &fHwKeyGroup[3]};
    for (int *s : slots) {
        if (*s < 0)
            continue;
        uint8_t idx = (uint8_t)*s;
        sendMsg(MM_KEY_DEL_REQ, &idx, 1, MM_KEY_DEL_CFM);
        *s = -1;
    }
}

int ItlAic::setControlPort(bool open)
{
    uint8_t req[2] = {fApIdx, (uint8_t)open};
    int err = sendMsg(ME_SET_CONTROL_PORT_REQ, req, sizeof(req), ME_SET_CONTROL_PORT_CFM);
    if (!err)
        fPortOpen = open;
    AICLOG("control port sta %u open %d: err %d", fApIdx, open, err);
    return err;
}

int ItlAic::aic_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
    ItlAic *that = fromIC(ic);
    enum ieee80211_state ostate = ic->ic_state;

    // AUTH->ASSOC->RUN are driven by our injected responses; any other way back tears down.
    if (nstate <= IEEE80211_S_AUTH)
        that->fwDisconnect();

    switch (nstate) {
    case IEEE80211_S_SCAN:
        if (ostate == IEEE80211_S_SCAN && that->fScanning)
            return 0;
        ieee80211_set_link_state(ic, LINK_STATE_DOWN);
        ieee80211_node_cleanup(ic, ic->ic_bss);
        ic->ic_state = nstate;              // like iwn: do not chain to the default newstate
        if (that->fScanning)                // firmware ignores a second SCANU_START; its CFM ends this scan
            return 0;
        return that->startScan();
    case IEEE80211_S_AUTH: {
        int err = that->com.sc_newstate(ic, nstate, arg);
        if (!err && that->startConnect(ic->ic_bss)) {
            uint8_t body[6] = {0, 0, 2, 0, 1, 0};   // open system, seq 2, status 1 (failure)
            that->injectMgmt(IEEE80211_FC0_SUBTYPE_AUTH, body, sizeof(body));
        }
        return err;
    }
    default:
        return that->com.sc_newstate(ic, nstate, arg);
    }
}

#pragma mark - receive

mbuf_t ItlAic::makeMbuf(const uint8_t *data, uint32_t len)
{
    mbuf_t m = getController()->allocatePacket(len);
    if (!m)
        return nullptr;
    if (mbuf_copyback(m, 0, len, data, MBUF_DONTWAIT) != 0 ||
        mbuf_len(m) < MIN(len, (uint32_t)sizeof(struct ieee80211_frame) + 8)) {
        mbuf_freem(m);
        return nullptr;
    }
    return m;
}

void ItlAic::inputFrame(mbuf_t m, int rssi, uint16_t freq, bool hwdec, bool needReord)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct ieee80211_rxinfo rxi = {};
    struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
    rxi.rxi_flags = hwdec ? IEEE80211_RXI_HWDEC : 0;
    rxi.rxi_rssi = MAX(0, rssi + 100);
    rxi.rxi_chan = (uint8_t)ieee80211_mhz2ieee(freq, 0);
    struct ieee80211_node *ni = ieee80211_find_rxnode(ic, wh);

    // A-MPDU reordering, as Linux rwnx_rxdataind_aicwf() does it: QoS data the firmware flags need_reord
    // goes through a per-TID reorder window; any other QoS data first flushes that TID's window. Without
    // this, net80211 dropped every QoS frame with the BA ack policy ("no BA agreement", input error) and
    // the CCMP replay check dropped frames that arrived out of order (~1-2% loss, unstable TCP throughput).
    if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA &&
        !(wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_NODATA) && ieee80211_has_qos(wh) &&
        ic->ic_state == IEEE80211_S_RUN && ni == ic->ic_bss) {
        uint8_t tid = ieee80211_get_qos(wh) & IEEE80211_QOS_TID;
        uint16_t sn = letoh16(*(uint16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
        if (!(needReord && rxBaStart(ni, tid, sn))) {
            rxBaStop(ni, tid, true);        // deliver what the window holds, in order, before this frame
            rxi.rxi_flags |= IEEE80211_RXI_AMPDU_DONE;
        }
    }
    ieee80211_input(&ic->ic_if, m, ni, &rxi);
    ieee80211_release_node(ic, ni);
}

// net80211's reorder engine (ieee80211_input_ba) only runs for a TID with an agreed Block Ack
// session, normally set up by ieee80211_recv_addba_req(). The firmware answers the AP's ADDBA itself,
// so install the receive side here, like recv_addba_req() but without sending an ADDBA response.
// The window starts at the first flagged frame's sequence number, as Linux reord_need_check() does.
bool ItlAic::rxBaStart(struct ieee80211_node *ni, uint8_t tid, uint16_t ssn)
{
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    if (ba->ba_state == IEEE80211_BA_AGREED && ba->ba_buf)
        return true;
    rxBaStop(ni, tid, false);               // stale buffer from a previous association
    ba->ba_buf = (struct ieee80211_ba_buf *)malloc(IEEE80211_BA_MAX_WINSZ * sizeof(struct ieee80211_ba_buf), 0, 0);
    if (!ba->ba_buf)
        return false;                       // malloc() zeroes it
    ba->ba_ni = ni;
    ba->ba_token = 0;
    ba->ba_timeout_val = 0;                 // no inactivity timer: the firmware owns the session
    timeout_set(&ba->ba_to, ieee80211_rx_ba_timeout, ba);
    timeout_set(&ba->ba_gap_to, ieee80211_input_ba_gap_timeout, ba);
    ba->ba_gapwait = 0;
    ba->ba_winmiss = 0;
    ba->ba_missedsn = 0;
    ba->ba_winsize = IEEE80211_BA_MAX_WINSZ;   // 64, AICWF_REORDER_WINSIZE in Linux
    ba->ba_params = (ba->ba_winsize << IEEE80211_ADDBA_BUFSZ_SHIFT) | (tid << IEEE80211_ADDBA_TID_SHIFT);
    ba->ba_winstart = ssn;
    ba->ba_winend = (ba->ba_winstart + ba->ba_winsize - 1) & 0xfff;
    ba->ba_head = 0;
    ba->ba_state = IEEE80211_BA_AGREED;
    return true;
}

void ItlAic::rxBaStop(struct ieee80211_node *ni, uint8_t tid, bool deliver)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
    if (ba->ba_state == IEEE80211_BA_INIT && !ba->ba_buf)
        return;                             // hot path: QoS data outside an aggregate
    if (deliver && ba->ba_state == IEEE80211_BA_AGREED && ba->ba_buf) {
        struct mbuf_list ml = MBUF_LIST_INITIALIZER();
        ieee80211_ba_move_window(ic, ni, tid, (ba->ba_winstart + ba->ba_winsize) & 0xfff, &ml);
        if_input(&ic->ic_if, &ml);
    }
    ba->ba_state = IEEE80211_BA_INIT;
    timeout_del(&ba->ba_to);
    timeout_del(&ba->ba_gap_to);
    ba->ba_gapwait = 0;
    if (ba->ba_buf) {
        for (int i = 0; i < IEEE80211_BA_MAX_WINSZ; i++) {
            if (ba->ba_buf[i].m) {
                mbuf_freem(ba->ba_buf[i].m);
                ba->ba_buf[i].m = nullptr;
            }
        }
        ::free(ba->ba_buf);                 // net80211's free(), not OSObject::free()
        ba->ba_buf = nullptr;
    }
}

// Disconnect, new association, detach. net80211's node cleanup stops the timers but never frees
// ba_buf for a STA's BSS node, so the driver that created the buffers frees them.
void ItlAic::rxBaStopAll(bool deliver)
{
    struct ieee80211_node *ni = com.sc_ic.ic_bss;
    if (!ni)
        return;
    for (uint8_t tid = 0; tid < IEEE80211_NUM_TID; tid++)
        rxBaStop(ni, tid, deliver);
}

void ItlAic::injectMgmt(uint8_t subtype, const uint8_t *body, uint32_t blen)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    uint8_t buf[sizeof(struct ieee80211_frame) + 806] = {};
    if (!ni || blen > sizeof(buf) - sizeof(struct ieee80211_frame))
        return;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)buf;
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | subtype;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
    IEEE80211_ADDR_COPY(wh->i_addr1, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr2, ni->ni_bssid);
    IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
    memcpy(buf + sizeof(*wh), body, blen);
    mbuf_t m = makeMbuf(buf, sizeof(*wh) + blen);
    if (m)
        inputFrame(m, (int)ni->ni_rssi - 100, ni->ni_chan ? ni->ni_chan->ic_freq : 0, false);
}

void ItlAic::onConnectInd(const uint8_t *p, uint32_t plen)
{
    struct ieee80211com *ic = &com.sc_ic;
    if (plen < 828 || !fConnecting)
        return;
    fConnecting = false;
    uint16_t status = rd16(p);
    if (status != 0) {
        AICLOG("connect failed, status %u", status);
        if (ic->ic_state == IEEE80211_S_AUTH) {
            uint8_t body[6] = {0, 0, 2, 0, (uint8_t)status, (uint8_t)(status >> 8)};
            injectMgmt(IEEE80211_FC0_SUBTYPE_AUTH, body, sizeof(body));
        }
        return;
    }
    fFwConnected = true;
    fDbgTx = fDbgRx = 0;
    rxBaStopAll(false);                     // new association: sequence numbers start over
    fVifIdx = p[9];
    fApIdx = p[10];
    if (ic->ic_state != IEEE80211_S_AUTH) {
        AICLOG("connect indication in state %d, leaving", ic->ic_state);
        fwDisconnect();
        return;
    }
    uint8_t auth[6] = {0, 0, 2, 0, 0, 0};
    injectMgmt(IEEE80211_FC0_SUBTYPE_AUTH, auth, sizeof(auth));
    if (ic->ic_state == IEEE80211_S_ASSOC) {
        uint32_t reqLen = rd16(p + 14), rspLen = rd16(p + 16);
        if (reqLen > 800)
            reqLen = 800;
        if (reqLen + rspLen > 800)
            rspLen = 800 - reqLen;
        uint8_t body[6 + 800];
        wr16(body, ic->ic_bss->ni_capinfo);
        wr16(body + 2, 0);
        wr16(body + 4, rd16(p + 820) | 0xc000);
        memcpy(body + 6, p + 20 + reqLen, rspLen);
        injectMgmt(IEEE80211_FC0_SUBTYPE_ASSOC_RESP, body, 6 + rspLen);
    }
    AICLOG("connected, ap sta %u vif %u, state %d", fApIdx, fVifIdx, ic->ic_state);
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    if (!(ic->ic_flags & IEEE80211_F_RSNON))
        setControlPort(true);
    if (fPendingEapol) {
        mbuf_t m = fPendingEapol;
        fPendingEapol = nullptr;
        inputFrame(m, (int)ic->ic_bss->ni_rssi - 100, ic->ic_bss->ni_chan->ic_freq, false);
    }
}

void ItlAic::onDisconnectInd(const uint8_t *p, uint32_t plen)
{
    struct ieee80211com *ic = &com.sc_ic;
    uint16_t reason = plen >= 2 ? rd16(p) : IEEE80211_REASON_UNSPECIFIED;
    if (!fFwConnected)                      // answer to our own SM_DISCONNECT_REQ
        return;
    AICLOG("firmware disconnected, reason %u", reason);
    rxBaStopAll(false);
    fFwConnected = false;
    fPortOpen = false;
    deleteHwKeys();
    if (ic->ic_state >= IEEE80211_S_AUTH) {
        // net80211's deauth handling notifies WCL and retries the join.
        uint8_t body[2] = {(uint8_t)reason, (uint8_t)(reason >> 8)};
        injectMgmt(IEEE80211_FC0_SUBTYPE_DEAUTH, body, sizeof(body));
    }
}

void ItlAic::handleMsg(uint16_t id, const uint8_t *p, uint32_t plen)
{
    struct ieee80211com *ic = &com.sc_ic;
    switch (id) {
    case SCANU_RESULT_IND: {
        // u16 length, u16 framectrl, u16 center_freq, u8 band, u8 sta_idx, u8 inst_nbr, s8 rssi, pad, frame
        if (plen < 12 || 12u + rd16(p) > plen || rd16(p) < 36)
            break;
        mbuf_t m = makeMbuf(p + 12, rd16(p));
        if (m)
            inputFrame(m, (int8_t)p[9], rd16(p + 4), false);
        break;
    }
    case SCANU_START_CFM:
        fScanning = false;
        if (ic->ic_state == IEEE80211_S_SCAN && (ic->ic_if.if_flags & IFF_RUNNING))
            ieee80211_end_scan(&ic->ic_if);
        break;
    case SM_CONNECT_IND:
        onConnectInd(p, plen);
        break;
    case SM_DISCONNECT_IND:
        onDisconnectInd(p, plen);
        break;
    default:
        break;
    }
}

// p: 60-byte hw_rxhdr then the 802.11 frame. @0 frame length, @14 rssi, @42 prim20 freq, @48 flags.
void ItlAic::handleData(const uint8_t *p, uint32_t len)
{
    struct ieee80211com *ic = &com.sc_ic;
    uint32_t flen = rd16(p);
    uint32_t rxFlags = rd32(p + 48);
    bool isBeacon = (len >= kRxHdrLen + sizeof(struct ieee80211_frame) + 12) &&
        ((p[kRxHdrLen] & (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK)) ==
         (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON));
    if (fDbgRx < 40 && len >= kRxHdrLen + 24 &&
        ((p[kRxHdrLen] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA || isBeacon)) {
        fDbgRx++;
        const uint8_t *f = p + kRxHdrLen;
        AICLOG("rx fc %02x%02x len %u flags %08x st %08x a1 %s iv %02x%02x%02x%02x", f[0], f[1], flen,
               rxFlags, rd32(p + 36), ether_sprintf(f + 4), f[24], f[25], f[26], f[27]);
    }
    if (len < kRxHdrLen + flen || flen < sizeof(struct ieee80211_frame) ||
        (!(rxFlags & (1u << 6)) && !isBeacon))
        return;                             // not flagged for upload (except beacons)
    const uint8_t *fr = p + kRxHdrLen;
    mbuf_t m = makeMbuf(fr, flen);
    if (!m)
        return;
    if (fConnecting && (fr[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
        // EAPOL message 1 can overtake SM_CONNECT_IND, which travels on the other pipe.
        if (fPendingEapol)
            mbuf_freem(fPendingEapol);
        fPendingEapol = m;
        return;
    }
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) {
        mbuf_freem(m);
        return;
    }
    inputFrame(m, (int8_t)p[14], rd16(p + 42), (fr[1] & IEEE80211_FC1_PROTECTED) != 0,
               (rd32(p + 48) & (1u << 5)) != 0);   // hw_rxhdr flags_need_reord
}

#pragma mark - transmit

void ItlAic::aic_start(struct _ifnet *ifp)
{
    ItlAic *that = fromIC((struct ieee80211com *)ifp);
    that->getMainCommandGate()->runAction(aic_start_task, ifp);
}

IOReturn ItlAic::aic_start_task(OSObject *, void *arg0, void *, void *, void *)
{
    struct _ifnet *ifp = (struct _ifnet *)arg0;
    struct ieee80211com *ic = (struct ieee80211com *)ifp;
    ItlAic *that = fromIC(ic);
    mbuf_t m;

    // The firmware does its own auth/assoc; net80211's management frames are not sent.
    while ((m = mq_dequeue(&ic->ic_mgtq)) != NULL) {
        struct ieee80211_node *ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
        mbuf_freem(m);
        if (ni)
            ieee80211_release_node(ic, ni);
    }
    while ((m = ifq_dequeue(&ifp->if_snd)) != NULL) {
        if (that->fStopping || !(ifp->if_flags & IFF_RUNNING) || ic->ic_state != IEEE80211_S_RUN ||
            !that->fFwConnected) {
            mbuf_freem(m);
            if (ifp->netStat)
                ifp->netStat->outputErrors++;
            continue;
        }
        that->txData(m);
    }
    return kIOReturnSuccess;
}

// USB header (u16 len, u8 0x01, u8 0) + hostdesc (28 B) + payload after the Ethernet header.
void ItlAic::txData(mbuf_t m)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    uint8_t eh[ETHER_HDR_LEN];
    size_t tot = mbuf_pkthdr_len(m);
    bool ok = false;
    if (tot >= ETHER_HDR_LEN && tot - ETHER_HDR_LEN + 32 <= kDataTxSize &&
        mbuf_copydata(m, 0, ETHER_HDR_LEN, eh) == 0) {
        bool eapol = eh[12] == 0x88 && eh[13] == 0x8e;
        if ((ic->ic_flags & IEEE80211_F_RSNON) && !fPortOpen && !eapol) {
            mbuf_freem(m);                  // port closed until the 4-way handshake is done
            return;
        }
        uint32_t plen = (uint32_t)(tot - ETHER_HDR_LEN), total = 32 + plen;
        uint8_t *b = (uint8_t *)fDataTxBuf->getBytesNoCopy();
        memset(b, 0, 32);
        wr16(b, (uint16_t)(total & 0x0fff));
        b[2] = 0x01;
        wr16(b + 4, (uint16_t)plen);        // hostdesc.packet_len
        memcpy(b + 12, eh, 6);              // eth_dest
        memcpy(b + 18, eh + 6, 6);          // eth_src
        b[24] = eh[12]; b[25] = eh[13];     // ethertype, network order
        b[26] = 1;                          // ac: best effort
        b[27] = 0;                          // tid
        b[28] = fVifIdx;
        b[29] = fApIdx;
        ok = mbuf_copydata(m, ETHER_HDR_LEN, plen, b + 32) == 0 && usbWrite(fDataOut, fDataTxBuf, total);
        if (fDbgTx < 40 || eapol) {
            fDbgTx++;
            AICLOG("tx %02x%02x len %u to %s port %d ok %d", eh[12], eh[13], plen, ether_sprintf(eh), fPortOpen, ok);
        }
    }
    mbuf_freem(m);
    if (ifp->netStat) {
        if (ok)
            ifp->netStat->outputPackets++;
        else
            ifp->netStat->outputErrors++;
    }
}

#pragma mark - keys

int ItlAic::aic_set_key(struct ieee80211com *ic, struct ieee80211_node *ni, struct ieee80211_key *k)
{
    ItlAic *that = fromIC(ic);
    uint8_t cipher;
    switch (k->k_cipher) {
    case IEEE80211_CIPHER_CCMP: cipher = MAC_CIPHER_CCMP; break;
    case IEEE80211_CIPHER_TKIP: cipher = MAC_CIPHER_TKIP; break;
    case IEEE80211_CIPHER_WEP40: cipher = MAC_CIPHER_WEP40; break;
    case IEEE80211_CIPHER_WEP104: cipher = MAC_CIPHER_WEP104; break;
    default: return 0;                      // IGTK/BIP: management frame protection is not set up
    }
    if ((k->k_flags & IEEE80211_KEY_IGTK) || !that->fFwConnected)
        return 0;
    bool group = (k->k_flags & IEEE80211_KEY_GROUP) != 0;
    uint8_t req[44] = {};                   // mm_key_add_req
    req[0] = group ? k->k_id : 0;
    req[1] = group ? 0xff : that->fApIdx;
    req[4] = (uint8_t)MIN(k->k_len, 32u);
    memcpy(req + 8, k->k_key, req[4]);
    req[40] = cipher;
    req[41] = that->fVifIdx;
    req[43] = group ? 0 : 1;
    uint8_t cfm[2] = {1, 0};                // status, hw_key_idx
    int err = that->sendMsg(MM_KEY_ADD_REQ, req, sizeof(req), MM_KEY_ADD_CFM, cfm, sizeof(cfm));
    if (err || cfm[0]) {
        AICLOG("MM_KEY_ADD failed (err %d status %u)", err, cfm[0]);
        return EIO;
    }
    AICLOG("key %s id %u cipher %u -> hw %u", group ? "group" : "pairwise", k->k_id, cipher, cfm[1]);
    if (group)
        that->fHwKeyGroup[k->k_id & 3] = cfm[1];
    else
        that->fHwKeyPairwise = cfm[1];
    if (group && !that->fPortOpen)
        that->setControlPort(true);
    return 0;
}

void ItlAic::aic_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni, struct ieee80211_key *k)
{
    ItlAic *that = fromIC(ic);
    int *slot = (k->k_flags & IEEE80211_KEY_GROUP) ? &that->fHwKeyGroup[k->k_id & 3] : &that->fHwKeyPairwise;
    if (*slot < 0)
        return;
    uint8_t idx = (uint8_t)*slot;
    *slot = -1;
    that->sendMsg(MM_KEY_DEL_REQ, &idx, 1, MM_KEY_DEL_CFM);
}
