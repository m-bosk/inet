//
// @authors: Enkhtuvshin Janchivnyambuu
//           Henning Puttnies
//           Peter Danielis
//           University of Rostock, Germany
// 

#include "Gptp.h"

#include "GptpPacket_m.h"

#include "inet/clock/model/SettableClock.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/clock/ClockUserModuleBase.h"
#include "inet/common/stlutils.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/ethernet/common/Ethernet.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/physicallayer/wired/ethernet/EthernetPhyHeader_m.h"

namespace inet {

Define_Module(Gptp);

simsignal_t Gptp::localTimeSignal = cComponent::registerSignal("localTime");
simsignal_t Gptp::timeDifferenceSignal = cComponent::registerSignal("timeDifference");
simsignal_t Gptp::rateRatioSignal = cComponent::registerSignal("rateRatio");
simsignal_t Gptp::peerDelaySignal = cComponent::registerSignal("peerDelay");

// MAC address:
//   01-80-C2-00-00-02 for TimeSync (ieee 802.1as-2020, 13.3.1.2)
//   01-80-C2-00-00-0E for Announce and Signaling messages, for Sync, Follow_Up, Pdelay_Req, Pdelay_Resp, and Pdelay_Resp_Follow_Up messages
const MacAddress Gptp::GPTP_MULTICAST_ADDRESS("01:80:C2:00:00:0E");

// EtherType:
//   0x8809 for TimeSync (ieee 802.1as-2020, 13.3.1.2)
//   0x88F7 for Announce and Signaling messages, for Sync, Follow_Up, Pdelay_Req, Pdelay_Resp, and Pdelay_Resp_Follow_Up messages

Gptp::~Gptp()
{
    cancelAndDeleteClockEvent(selfMsgDelayReq);
    cancelAndDeleteClockEvent(selfMsgSync);
    cancelAndDeleteClockEvent(requestMsg);
}

void Gptp::setMasterPortsFromPar()
{
    std::set<int> oldMasterPortIds = masterPortIds;
    auto v = check_and_cast<cValueArray *>(par("masterPorts").objectValue())->asStringVector();
    masterPortIds.clear();
    for (const auto& p : v) {
        auto nic = CHK(interfaceTable->findInterfaceByName(p.c_str()));
        int portId = nic->getInterfaceId();
        if (portId == slavePortId)
            throw cRuntimeError("Parameter error: the port '%s' specified both master and slave port", p.c_str());
        masterPortIds.insert(portId);
    }
    std::set<int> ids;
    std::set_difference(oldMasterPortIds.begin(), oldMasterPortIds.end(), masterPortIds.begin(), masterPortIds.end(), std::inserter(ids, ids.end()));
    for (auto id: ids) {
        auto nic = interfaceTable->getInterfaceById(id);
        nic->removeMulticastMacAddress(GPTP_MULTICAST_ADDRESS);
        nic->unsubscribe(transmissionEndedSignal, this);
        nic->unsubscribe(receptionEndedSignal, this);
    }
    ids.clear();
    std::set_difference(masterPortIds.begin(), masterPortIds.end(), oldMasterPortIds.begin(), oldMasterPortIds.end(), std::inserter(ids, ids.end()));
    for (auto id: ids) {
        auto nic = interfaceTable->getInterfaceById(id);
        nic->addMulticastMacAddress(GPTP_MULTICAST_ADDRESS);
        nic->subscribe(transmissionEndedSignal, this);
        nic->subscribe(receptionEndedSignal, this);
    }
}

void Gptp::setSlavePortFromPar()
{
    int oldSlavePortId = slavePortId;
    const char *str = par("slavePort");
    if (*str) {
        if (auto nic = interfaceTable->findInterfaceByName(str)) {
            slavePortId = nic->getInterfaceId();
            if (contains(masterPortIds, slavePortId))
                throw cRuntimeError("Parameter error: the port '%s' specified both master and slave port", str);
        }
        else
            throw cRuntimeError("Parameter error: the port '%s' not found in interface table", str);
    }
    else
        slavePortId = -1;
    if (oldSlavePortId != -1) {
        auto nic = interfaceTable->getInterfaceById(oldSlavePortId);
        nic->removeMulticastMacAddress(GPTP_MULTICAST_ADDRESS);
        nic->unsubscribe(transmissionEndedSignal, this);
        nic->unsubscribe(receptionEndedSignal, this);
    }
    if (slavePortId != -1) {
        auto nic = interfaceTable->getInterfaceById(slavePortId);
        nic->addMulticastMacAddress(GPTP_MULTICAST_ADDRESS);
        nic->subscribe(transmissionEndedSignal, this);
        nic->subscribe(receptionEndedSignal, this);
        if (slavePortId != -1 && requestMsg == nullptr)
            startSlavePort();
    }
    else {
        stopSlavePort();
    }
    peerDelay = 0;
    receivedTimeSync = CLOCKTIME_ZERO;
}

void Gptp::setGrandMasterFromPar()
{
    grandMaster = par("grandMaster");
    /* Only grandmaster in the domain can initialize the synchronization message periodically
     * so below condition checks whether it is grandmaster and then schedule first sync message */
    if (grandMaster) {
        gmRateRatio = 1.0;
        if (slavePortId != -1)
            throw cRuntimeError("Parameter error: Specified as GrandMaster, but the slave port also specified.");
        // Schedule Sync message to be sent
        selfMsgSync = new ClockEvent("selfMsgSync", GPTP_SELF_MSG_SYNC);

        clocktime_t scheduleSync = par("syncInitialOffset");
        //originTimestamp = clock->getClockTime() + scheduleSync;
        scheduleClockEventAfter(scheduleSync, selfMsgSync);
        stopSlavePort();
    }
    else {
        // BRIDGE NODE or SLAVE NODE
        cancelAndDeleteClockEvent(selfMsgSync);
        selfMsgSync = nullptr;
        if (slavePortId != -1 && requestMsg == nullptr)
            startSlavePort();
    }
}

void Gptp::startSlavePort()
{
        requestMsg = new ClockEvent("requestToSendSync", GPTP_REQUEST_TO_SEND_SYNC);

        // Schedule Pdelay_Req message is sent by slave port
        // without depending on node type which is grandmaster or bridge
        selfMsgDelayReq = new ClockEvent("selfMsgPdelay", GPTP_SELF_MSG_PDELAY_REQ);
        scheduleClockEventAfter(par("pdelayInitialOffset"), selfMsgDelayReq);
}

void Gptp::stopSlavePort()
{
        cancelAndDeleteClockEvent(requestMsg);
        requestMsg = nullptr;
        cancelAndDeleteClockEvent(selfMsgDelayReq);
        selfMsgDelayReq = nullptr;
}

void Gptp::handleParameterChange(const char *name)
{
    if (0 == strcmp(name, "slavePort"))
        setSlavePortFromPar();
    else if (0 == strcmp(name, "masterPorts"))
        setMasterPortsFromPar();
    else if (0 == strcmp(name, "grandMaster"))
        setGrandMasterFromPar();
    else if (0 == strcmp(name, "correctionField"))
        correctionField = par("correctionField");
    else if (0 == strcmp(name, "syncInterval"))
        syncInterval = par("syncInterval");
    else if (0 == strcmp(name, "pdelayInterval"))
        pdelayInterval = par("pdelayInterval");
    else if (0 == strcmp(name, "pDelayReqProcessingTime"))
        pDelayReqProcessingTime = par("pDelayReqProcessingTime");
    else if (0 == strcmp(name, "syncInitialOffset") || 0 == strcmp(name, "pdelayInitialOffset"))
        ;   // used directly
    else
        throw cRuntimeError("Parameter '%s' change unsupported", name);
}

void Gptp::initialize(int stage)
{
    ClockUserModuleBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        syncInterval = par("syncInterval");
        pdelayInterval = par("pdelayInterval");
        pDelayReqProcessingTime = par("pDelayReqProcessingTime");
        correctionField = par("correctionField");
        interfaceTable.reference(this, "interfaceTableModule", true);
        gmRateRatio = 1.0;
        peerDelay = 0;
        receivedTimeSync = CLOCKTIME_ZERO;
        WATCH(peerDelay);
    }
    if (stage == INITSTAGE_LINK_LAYER) {
        registerProtocol(Protocol::gptp, gate("socketOut"), gate("socketIn"));
        setSlavePortFromPar();
        setMasterPortsFromPar();
        setGrandMasterFromPar();
    }
}

void Gptp::handleSelfMessage(cMessage *msg)
{
    switch(msg->getKind()) {
        case GPTP_SELF_MSG_SYNC:
            ASSERT(grandMaster);
            // masterport:
            ASSERT(selfMsgSync == msg);
            sendSync();

            /* Schedule next Sync message at next sync interval
             * Grand master always works at simulation time */
            scheduleClockEventAfter(syncInterval, selfMsgSync);
            break;

        case GPTP_SELF_REQ_ANSWER_KIND:
            // masterport:
            sendPdelayResp(check_and_cast<GptpReqAnswerEvent*>(msg));
            delete msg;
            break;

        case GPTP_SELF_MSG_PDELAY_REQ:
            // slaveport:
            sendPdelayReq(); //TODO on slaveports only
            scheduleClockEventAfter(pdelayInterval, selfMsgDelayReq);
            break;

        default:
            throw cRuntimeError("Unknown self message (%s)%s, kind=%d", msg->getClassName(), msg->getName(), msg->getKind());
    }
}

void Gptp::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    else {
        Packet *packet = check_and_cast<Packet *>(msg);
        auto gptp = packet->peekAtFront<GptpBase>();
        auto gptpMessageType = gptp->getMessageType();
        auto incomingNicId = packet->getTag<InterfaceInd>()->getInterfaceId();

        if (incomingNicId == slavePortId) {
            // slave port
            switch (gptpMessageType) {
                case GPTPTYPE_SYNC:
                    processSync(packet, check_and_cast<const GptpSync *>(gptp.get()));
                    break;
                case GPTPTYPE_FOLLOW_UP:
                    processFollowUp(packet, check_and_cast<const GptpFollowUp *>(gptp.get()));
                    // Send a request to send Sync message
                    // through other gptp Ethernet interfaces
                    if(!masterPortIds.empty()) {
                        // BRIDGE NODE
                        sendSync();
                    }
                    break;
                case GPTPTYPE_PDELAY_REQ:
                    EV_ERROR << CHK(omnetpp::cEnum::get("inet::GptpMessageType")->getStringFor((int)gptpMessageType)) << " arrived on slave port, dropped it\n";
                    break;
                case GPTPTYPE_PDELAY_RESP:
                    processPdelayResp(packet, check_and_cast<const GptpPdelayResp *>(gptp.get()));
                    break;
                case GPTPTYPE_PDELAY_RESP_FOLLOW_UP:
                    processPdelayRespFollowUp(packet, check_and_cast<const GptpPdelayRespFollowUp *>(gptp.get()));
                    break;
                default:
                    throw cRuntimeError("Unknown gPTP packet type: %d", (int)(gptpMessageType));
            }
        }
        else if (contains(masterPortIds, incomingNicId)) {
            // master port
            switch (gptpMessageType) {
                case GPTPTYPE_PDELAY_REQ:
                    processPdelayReq(packet, check_and_cast<const GptpPdelayReq *>(gptp.get()));
                    break;
                case GPTPTYPE_SYNC:
                case GPTPTYPE_FOLLOW_UP:
                case GPTPTYPE_PDELAY_RESP:
                case GPTPTYPE_PDELAY_RESP_FOLLOW_UP:
                    EV_ERROR << CHK(omnetpp::cEnum::get("inet::GptpMessageType")->getStringFor((int)gptpMessageType)) << " arrived on a master port, dropped it\n";
                    break;
                default:
                    throw cRuntimeError("Unknown gPTP packet type: %d", (int)(gptpMessageType));
            }
        }
        else {
            // passive port
            EV_ERROR << "Message " << msg->getClassAndFullName() << " arrived on passive port " << incomingNicId << ", dropped\n";
        }
        delete msg;
    }
}

void Gptp::sendPacketToNIC(Packet *packet, int portId)
{
    auto networkInterface = interfaceTable->getInterfaceById(portId);
    EV_INFO << "Sending " << packet << " to output interface = " << networkInterface->getInterfaceName() << ".\n";
    packet->addTag<InterfaceReq>()->setInterfaceId(portId);
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::gptp);
    packet->addTag<DispatchProtocolInd>()->setProtocol(&Protocol::gptp);
    auto protocol = networkInterface->getProtocol();
    if (protocol != nullptr)
        packet->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(protocol);
    else
        packet->removeTagIfPresent<DispatchProtocolReq>();
    send(packet, "socketOut");
}

void Gptp::sendSync()
{
    auto packet = new Packet("GptpSync");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GptpSync>();
    /* OriginTimestamp always get Sync departure time from grand master */
    if (slavePortId == -1) {
        // MASTER NODE
        originTimestamp = clock->getClockTime();
    }
    gptp->setOriginTimestamp(CLOCKTIME_ZERO);
    gptp->setSequenceId(sequenceId++);

    sentTimeSyncSync = clock->getClockTime();
    packet->insertAtFront(gptp);

    for (auto port: masterPortIds)
        sendPacketToNIC(packet->dup(), port);
    delete packet;

    // The sendFollowUp(portId) called by receiveSignal(), when GptpSync sent
}

void Gptp::sendFollowUp(int portId, const GptpSync *sync, clocktime_t preciseOriginTimestamp)
{
    auto packet = new Packet("GptpFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GptpFollowUp>();
    gptp->setPreciseOriginTimestamp(preciseOriginTimestamp);
    gptp->setSequenceId(sync->getSequenceId());

    if (slavePortId == -1) {
        // MASTER NODE
        gptp->setCorrectionField(CLOCKTIME_ZERO);
    }
    else if (!masterPortIds.empty()) {
        // BRIDGE NODE
        /**************** Correction field calculation *********************************************
         * It is calculated by adding peer delay, residence time and packet transmission time      *
         * correctionField(i)=correctionField(i-1)+peerDelay+(timeReceivedSync-timeSentSync)*(1-f) *
         *******************************************************************************************/
        // gptp->setCorrectionField(correctionField + peerDelay + sentTimeSyncSync - receivedTimeSync);  // TODO revise it!!! see prev. comment, where is the (1-f),  ???
        gptp->setCorrectionField(CLOCKTIME_ZERO);  // TODO revise it!!! see prev. comment, where is the (1-f),  ???
    }
    gptp->setRateRatio(gmRateRatio);
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
}

void Gptp::sendPdelayResp(GptpReqAnswerEvent* req)
{
    int portId = req->getPortId();
    auto packet = new Packet("GptpPdelayResp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GptpPdelayResp>();
    //??? gptp->setSentTime(clock->getClockTime());
    gptp->setRequestingPortIdentity(req->getSourcePortIdentity());
    gptp->setSequenceId(req->getSequenceId());
    gptp->setRequestReceiptTimestamp(req->getIngressTimestamp());
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
    // The sendPdelayRespFollowUp(portId) called by receiveSignal(), when GptpPdelayResp sent
}

void Gptp::sendPdelayRespFollowUp(int portId, const GptpPdelayResp* resp)
{
    auto packet = new Packet("GptpPdelayRespFollowUp");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GptpPdelayRespFollowUp>();
    auto now = clock->getClockTime();
    gptp->setResponseOriginTimestamp(now);
    gptp->setRequestingPortIdentity(resp->getRequestingPortIdentity());
    gptp->setSequenceId(resp->getSequenceId());
    packet->insertAtFront(gptp);
    sendPacketToNIC(packet, portId);
}

void Gptp::sendPdelayReq()
{
    ASSERT(slavePortId != -1);
    auto packet = new Packet("GptpPdelayReq");
    packet->addTag<MacAddressReq>()->setDestAddress(GPTP_MULTICAST_ADDRESS);
    auto gptp = makeShared<GptpPdelayReq>();
    gptp->setCorrectionField(CLOCKTIME_ZERO);
    //save and send IDs
    PortIdentity portId;
    portId.clockIdentity = getId();
    portId.portNumber = slavePortId;
    gptp->setSourcePortIdentity(portId);
    lastSentPdelayReqSequenceId = sequenceId++;
    gptp->setSequenceId(lastSentPdelayReqSequenceId);
    packet->insertAtFront(gptp);
    pdelayReqEventEgressTimestamp = clock->getClockTime();
    rcvdPdelayResp = false;
    sendPacketToNIC(packet, slavePortId);
}


void Gptp::processSync(Packet *packet, const GptpSync* gptp)
{
    rcvdGptpSync = true;
    lastReceivedGptpSyncSequenceId = gptp->getSequenceId();

    peerSentTimeSync = gptp->getOriginTimestamp();  // TODO this is unfilled in two-step mode
    syncIngressTimestamp = packet->getTag<GptpIngressTimeInd>()->getArrivalClockTime();
}

void Gptp::processFollowUp(Packet *packet, const GptpFollowUp* gptp)
{
    // check: is received the GptpSync for this GptpFollowUp?
    if (!rcvdGptpSync) {
        EV_WARN << "GptpFollowUp arrived without GptpSync, dropped";
        return;
    }
    // verify IDs
    if (gptp->getSequenceId() != lastReceivedGptpSyncSequenceId) {
        EV_WARN << "GptpFollowUp arrived with invalid sequence ID, dropped";
        return;
    }


    peerSentTimeSync = gptp->getPreciseOriginTimestamp();
    correctionField = gptp->getCorrectionField();
    receivedRateRatio = gptp->getRateRatio();

    synchronize();

    EV_INFO << "############## FOLLOW_UP ################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC - " << newLocalTimeAtTimeSync << endl;
    EV_INFO << "ORIGIN TIME SYNC         - " << originTimestamp << endl;
    EV_INFO << "CORRECTION FIELD         - " << correctionField << endl;
    EV_INFO << "PROPAGATION DELAY        - " << peerDelay << endl;

    rcvdGptpSync = false;
}

void Gptp::synchronize()
{
    simtime_t now = simTime();
    clocktime_t origNow = clock->getClockTime();
    clocktime_t residenceTime = origNow - syncIngressTimestamp;

    emit(timeDifferenceSignal, CLOCKTIME_AS_SIMTIME(origNow) - now);

    /************** Time synchronization *****************************************
     * Local time is adjusted using peer delay, correction field, residence time *
     * and packet transmission time based departure time of Sync message from GM *
     *****************************************************************************/
    clocktime_t newTime = peerSentTimeSync + peerDelay + correctionField + residenceTime;

    check_and_cast<SettableClock *>(clock.get())->setClockTime(newTime);

    // TODO computeGmRateRatio:
    gmRateRatio = (origNow - newLocalTimeAtTimeSync) / (syncIngressTimestamp - receivedTimeSync);
    gmRateRatio = 1.0 / gmRateRatio;

    oldLocalTimeAtTimeSync = origNow;
    newLocalTimeAtTimeSync = clock->getClockTime();
    receivedTimeSync = syncIngressTimestamp;

    // adjust local timestamps, too
    pdelayReqEventEgressTimestamp += newLocalTimeAtTimeSync - oldLocalTimeAtTimeSync;

    /************** Rate ratio calculation *************************************
     * It is calculated based on interval between two successive Sync messages *
     ***************************************************************************/

    EV_INFO << "############## SYNC #####################################"<< endl;
    EV_INFO << "RECEIVED TIME AFTER SYNC   - " << newLocalTimeAtTimeSync << endl;
    EV_INFO << "RECEIVED SIM TIME          - " << now << endl;
    EV_INFO << "ORIGIN TIME SYNC           - " << peerSentTimeSync << endl;
    EV_INFO << "RESIDENCE TIME             - " << residenceTime << endl;
    EV_INFO << "CORRECTION FIELD           - " << correctionField << endl;
    EV_INFO << "PROPAGATION DELAY          - " << peerDelay << endl;
    EV_INFO << "TIME DIFFERENCE TO SIMTIME - " << CLOCKTIME_AS_SIMTIME(newLocalTimeAtTimeSync) - now << endl;
    EV_INFO << "RATE RATIO                 - " << gmRateRatio << endl;

    emit(rateRatioSignal, gmRateRatio);
    emit(localTimeSignal, CLOCKTIME_AS_SIMTIME(newLocalTimeAtTimeSync));
    emit(timeDifferenceSignal, CLOCKTIME_AS_SIMTIME(newLocalTimeAtTimeSync) - now);
}

void Gptp::processPdelayReq(Packet *packet, const GptpPdelayReq* gptp)
{
    peerRequestReceiptTimestamp = clock->getClockTime();

    auto resp = new GptpReqAnswerEvent("selfMsgPdelayResp", GPTP_SELF_REQ_ANSWER_KIND);
    resp->setPortId(packet->getTag<InterfaceInd>()->getInterfaceId());
    resp->setIngressTimestamp(packet->getTag<GptpIngressTimeInd>()->getArrivalClockTime());
    resp->setSourcePortIdentity(gptp->getSourcePortIdentity());
    resp->setSequenceId(gptp->getSequenceId());

    scheduleClockEventAfter(pDelayReqProcessingTime, resp);
}

void Gptp::processPdelayResp(Packet *packet, const GptpPdelayResp* gptp)
{
    // verify IDs
    if (gptp->getRequestingPortIdentity().clockIdentity != getId() || gptp->getRequestingPortIdentity().portNumber != slavePortId) {
        EV_WARN << "GptpPdelayResp arrived with invalid PortIdentity, dropped";
        return;
    }
    if (gptp->getSequenceId() != lastSentPdelayReqSequenceId) {
        EV_WARN << "GptpPdelayResp arrived with invalid sequence ID, dropped";
        return;
    }

    rcvdPdelayResp = true;
    pdelayRespEventIngressTimestamp = packet->getTag<GptpIngressTimeInd>()->getArrivalClockTime();
    peerRequestReceiptTimestamp = gptp->getRequestReceiptTimestamp();
    peerResponseOriginTimestamp = CLOCKTIME_ZERO;
}

void Gptp::processPdelayRespFollowUp(Packet *packet, const GptpPdelayRespFollowUp* gptp)
{
    if (!rcvdPdelayResp) {
        EV_WARN << "GptpPdelayRespFollowUp arrived without GptpPdelayResp, dropped";
        return;
    }
    // verify IDs
    if (gptp->getRequestingPortIdentity().clockIdentity != getId() || gptp->getRequestingPortIdentity().portNumber != slavePortId) {
        EV_WARN << "GptpPdelayRespFollowUp arrived with invalid PortIdentity, dropped";
        return;
    }
    if (gptp->getSequenceId() != lastSentPdelayReqSequenceId) {
        EV_WARN << "GptpPdelayRespFollowUp arrived with invalid sequence ID, dropped";
        return;
    }

    peerResponseOriginTimestamp = gptp->getResponseOriginTimestamp();

    // computePropTime():
    peerDelay = (gmRateRatio * (pdelayRespEventIngressTimestamp - pdelayReqEventEgressTimestamp) - (peerResponseOriginTimestamp - peerRequestReceiptTimestamp)) / 2.0;

    EV_INFO << "RATE RATIO                       - " << gmRateRatio << endl;
    EV_INFO << "pdelayReqEventEgressTimestamp    - " << pdelayReqEventEgressTimestamp << endl;
    EV_INFO << "peerResponseOriginTimestamp      - " << peerResponseOriginTimestamp << endl;
    EV_INFO << "pdelayRespEventIngressTimestamp  - " << pdelayRespEventIngressTimestamp << endl;
    EV_INFO << "peerRequestReceiptTimestamp      - " << peerRequestReceiptTimestamp << endl;
    EV_INFO << "PEER DELAY                       - " << peerDelay << endl;

    emit(peerDelaySignal, CLOCKTIME_AS_SIMTIME(peerDelay));
}

void Gptp::receiveSignal(cComponent *source, simsignal_t signal, cObject *obj, cObject *details)
{
    Enter_Method("%s", cComponent::getSignalName(signal));

    if (signal == receptionEndedSignal) {
        auto signal = check_and_cast<cPacket *>(obj);
        auto packet = check_and_cast_nullable<Packet *>(signal->getEncapsulatedPacket());
        if (packet) {
            packet->addTagIfAbsent<GptpIngressTimeInd>()->setArrivalClockTime(clock->getClockTime());
        }
    }
    else if (signal == transmissionEndedSignal) {
        auto signal = check_and_cast<cPacket *>(obj);
        auto packet = check_and_cast_nullable<Packet *>(signal->getEncapsulatedPacket());
        if (packet) {
            auto protocol = packet->getTag<PacketProtocolTag>()->getProtocol();
            if (*protocol == Protocol::ethernetPhy) {
                const auto& ethPhyHeader = packet->peekAtFront<physicallayer::EthernetPhyHeader>();
                const auto& ethMacHeader = packet->peekAt<EthernetMacHeader>(ethPhyHeader->getChunkLength());
                if (ethMacHeader->getTypeOrLength() == ETHERTYPE_GPTP) {
                    const auto& gptp = packet->peekAt<GptpBase>(ethPhyHeader->getChunkLength() + ethMacHeader->getChunkLength());
                    int portId = getContainingNicModule(check_and_cast<cModule*>(source))->getInterfaceId();
                    switch (gptp->getMessageType()) {
                        case GPTPTYPE_PDELAY_RESP: {
                            auto gptpResp = dynamicPtrCast<const GptpPdelayResp>(gptp);
                            sendPdelayRespFollowUp(portId, gptpResp.get());
                            break;
                        }
                        case GPTPTYPE_SYNC: {
                            auto gptpSync = dynamicPtrCast<const GptpSync>(gptp);
                            sendFollowUp(portId, gptpSync.get(), clock->getClockTime());
                            break;
                        }
                        case GPTPTYPE_PDELAY_REQ:
                            if (portId == slavePortId)
                                pdelayReqEventEgressTimestamp = clock->getClockTime();
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
}

}

