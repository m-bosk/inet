//
// Copyright (C) 2020 OpenSim Ltd.
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

#include "inet/common/packet/PacketFilter.h"

// TODO: delme
#include "inet/networklayer/ipv4/Ipv4Header_m.h"

namespace inet {

void PacketFilter::setPattern(const char *packetPattern, const char *chunkPattern)
{
    packetDissectorCallback = new PacketDissectorCallback(this);
    dynamicExpressionResolver = new DynamicExpressionResolver(this);
    filterExpression.parse(packetPattern, dynamicExpressionResolver);
}

bool PacketFilter::matches(const cPacket *cpacket) const
{
    this->cpacket = cpacket;
    protocolToChunkMap.clear();
    classNameToChunkMap.clear();
    if (auto packet = dynamic_cast<const Packet *>(cpacket)) {
        PacketDissector packetDissector(ProtocolDissectorRegistry::globalRegistry, *packetDissectorCallback);
        packetDissector.dissectPacket(const_cast<Packet *>(packet));
    }
    return filterExpression.evaluate().boolValue();
}

void PacketFilter::PacketDissectorCallback::visitChunk(const Ptr<const Chunk>& chunk, const Protocol *protocol)
{
    packetFilter->protocolToChunkMap.insert({protocol, const_cast<Chunk *>(chunk.get())});
    auto className = chunk->getClassName();
    const char *colon = strrchr(className, ':');
    if (colon != nullptr)
        className = colon + 1;
    packetFilter->classNameToChunkMap.insert({className, const_cast<Chunk *>(chunk.get())});
}

cValue PacketFilter::DynamicExpressionResolver::readVariable(cExpression::Context *context, const char *name)
{
    if (!strcmp(name, "pk"))
        return const_cast<cPacket *>(packetFilter->cpacket);
    else {
        if (isupper(name[0])) {
            auto it = packetFilter->classNameToChunkMap.find(name);
            if (it != packetFilter->classNameToChunkMap.end())
                return it->second;
        }
        else {
            auto protocol = Protocol::findProtocol(name);
            if (protocol != nullptr) {
                auto it = packetFilter->protocolToChunkMap.find(protocol);
                if (it != packetFilter->protocolToChunkMap.end())
                    return it->second;
            }
        }
        // TODO add reflection on the packet
        return ResolverBase::readVariable(context, name);
    }
}

cValue PacketFilter::DynamicExpressionResolver::readVariable(cExpression::Context *context, const char *name, intval_t index)
{
    if (isupper(name[0])) {
        if (index < packetFilter->classNameToChunkMap.count(name)) {
            auto it = packetFilter->classNameToChunkMap.lower_bound(name);
            while (index-- > 0) it++;
            return it->second;
        }
    }
    else {
        auto protocol = Protocol::findProtocol(name);
        if (protocol != nullptr) {
            if (index != packetFilter->protocolToChunkMap.count(protocol)) {
                auto it = packetFilter->protocolToChunkMap.lower_bound(protocol);
                while (index-- > 0) it++;
                return it->second;
            }
        }
    }
    return ResolverBase::readVariable(context, name, index);
}

cValue PacketFilter::DynamicExpressionResolver::readMember(cExpression::Context *context, const cValue &object, const char *name)
{
    if (object.getType() == cValue::OBJECT) {
        if (dynamic_cast<Packet *>(object.objectValue())) {
            if (cObjectFactory::find(name, "inet", false) != nullptr) {
                auto it = packetFilter->classNameToChunkMap.find(name);
                if (it != packetFilter->classNameToChunkMap.end())
                    return it->second;
                else
                    return static_cast<cObject *>(nullptr);
            }
            else {
                auto protocol = Protocol::findProtocol(name);
                if (protocol != nullptr) {
                    auto it = packetFilter->protocolToChunkMap.find(protocol);
                    if (it != packetFilter->protocolToChunkMap.end())
                        return it->second;
                    else
                        return static_cast<cObject *>(nullptr);
                }
            }
        }
        // reflection
        auto cobject = object.objectValue();
        auto classDescriptor = cobject->getDescriptor();
        int field = classDescriptor->findField(name);
        if (field != -1) {
            const char *fieldTypeString = classDescriptor->getFieldTypeString(field);
            auto fieldValue = classDescriptor->getFieldValueAsString(toAnyPtr(cobject), field, 0);
            // KLUDGE TODO other cases
            if (!strcmp(fieldTypeString, "unsigned short"))
                return atoi(fieldValue.c_str());
            else if (!strcmp(fieldTypeString, "inet::b"))
                return cValue(atol(fieldValue.c_str()), fieldValue.substr(fieldValue.size() - 1).c_str());
            else
                return fieldValue;
        }
        else
            return ResolverBase::readMember(context, object, name);
    }
    else
        return ResolverBase::readMember(context, object, name);
}

} // namespace inet

