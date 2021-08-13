//
// Copyright (C) 2005 OpenSim Ltd.
// Copyright (C) 2010 Alfonso Ariza
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#include "inet/linklayer/common/OmittedIeee8021dQosClassifier.h"

#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/EtherType_m.h"
#include "inet/linklayer/common/UserPriority.h"
#include "inet/linklayer/common/UserPriorityTag_m.h"
#include "inet/networklayer/common/IpProtocolId_m.h"

namespace inet {

Define_Module(OmittedIeee8021dQosClassifier);

void OmittedIeee8021dQosClassifier::initialize()
{
    // TODO parameters
}

void OmittedIeee8021dQosClassifier::handleMessage(cMessage *msg)
{
    auto packet = check_and_cast<Packet *>(msg);
    packet->removeTagIfPresent<UserPriorityReq>();
    send(msg, "out");
}



void OmittedIeee8021dQosClassifier::handleRegisterService(const Protocol& protocol, cGate *g, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterService");
    if (!strcmp("in", g->getName()))
        registerService(protocol, gate("out"), servicePrimitive);
    else
        throw cRuntimeError("Unknown gate: %s", g->getName());
}

void OmittedIeee8021dQosClassifier::handleRegisterProtocol(const Protocol& protocol, cGate *g, ServicePrimitive servicePrimitive)
{
    Enter_Method("handleRegisterProtocol");
    if (!strcmp("in", g->getName()))
        registerProtocol(protocol, gate("out"), servicePrimitive);
    else
        throw cRuntimeError("Unknown gate: %s", g->getName());
}

} // namespace inet
