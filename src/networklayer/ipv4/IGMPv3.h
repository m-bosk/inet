// Copyright (C) 2012 - 2013 Brno University of Technology (http://nes.fit.vutbr.cz/ansa)
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
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

/**
 * @file IGMPv3.h
 * @author Adam Malik(mailto:towdie13@gmail.com), Vladimir Vesely (mailto:ivesely@fit.vutbr.cz)
 * @date 12.5.2013
 * @brief
 * @detail
 */

#ifndef INET_IGMPV3_H
#define INET_IGMPV3_H

#include "INETDefs.h"
#include "INotifiable.h"
#include "IPv4Address.h"
#include "IGMPMessage.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"

#include <set>

class IInterfaceTable;
class IRoutingTable;
class NotificationBoard;

class INET_API IGMPv3 : public cSimpleModule, protected INotifiable
{
    protected:
        typedef std::vector<IPv4Address> IPv4AddressVector;

        enum RouterState
        {
            IGMPV3_RS_INITIAL,
            IGMPV3_RS_QUERIER,
            IGMPV3_RS_NON_QUERIER,
        };

        enum RouterGroupState
        {
            IGMPV3_RGS_NO_MEMBERS_PRESENT,
            IGMPV3_RGS_MEMBERS_PRESENT,
            IGMPV3_RGS_CHECKING_MEMBERSHIP,
        };

        enum HostGroupState
        {
            IGMPV3_HGS_NON_MEMBER,
            IGMPV3_HGS_DELAYING_MEMBER,
            IGMPV3_HGS_IDLE_MEMBER,
        };

        enum FilterMode
        {
            IGMPV3_FM_INCLUDE,
            IGMPV3_FM_EXCLUDE,
        };

        enum ReportType
        {
            IGMPV3_RT_IS_IN = 1,
            IGMPV3_RT_IS_EX = 2,
            IGMPV3_RT_TO_IN = 3,
            IGMPV3_RT_TO_EX = 4,
            IGMPV3_RT_ALLOW = 5,
            IGMPV3_RT_BLOCK = 6,
        };

        struct HostGroupData
        {
            IGMPv3 *owner;
            IPv4Address groupAddr;
            FilterMode filter;
            IPv4AddressVector sourceAddressList;
            HostGroupState state;
            cMessage *timer; // for scheduling responses to Group-Specific and Group-and-Source-Specific Queries

            HostGroupData(IGMPv3 *owner, IPv4Address group);
            virtual ~HostGroupData();
            std::string getStateInfo() const;
        };
        typedef std::map<IPv4Address,HostGroupData*> GroupToHostDataMap;

        struct SourceRecord
        {
            IGMPv3 *owner;
            IPv4Address sourceAddr;
            cMessage *sourceTimer;

            SourceRecord(IGMPv3 *owner, const IPv4Address &source);
            virtual ~SourceRecord();
        };
        typedef std::map<IPv4Address, SourceRecord*> SourceToSourceRecordMap;

        struct RouterGroupData
        {
            IGMPv3 *owner;
            InterfaceEntry *ie;
            IPv4Address groupAddr;
            FilterMode filter;
            RouterGroupState state;
            cMessage *timer;
            SourceToSourceRecordMap sources; // XXX should map source addresses to source timers
                                          // i.e. map<IPv4Address,cMessage*>

            RouterGroupData(IGMPv3 *owner, IPv4Address group);
            virtual ~RouterGroupData();
            std::string getStateInfo() const;
            void collectForwardedSources(IPv4MulticastSourceList &result) const;

            private:
            void printSourceList(std::ostream &out, bool withRunningTimer) const;
        };
        typedef std::map<IPv4Address, RouterGroupData*> GroupToRouterDataMap;

        struct HostInterfaceData
        {
            IGMPv3 *owner;
            int multicastRouterVersion;
            GroupToHostDataMap groups;
            cMessage *generalQueryTimer; // for scheduling responses to General Queries

            HostInterfaceData(IGMPv3 *owner);
            virtual ~HostInterfaceData();
        };
        typedef std::map<int, HostInterfaceData*> InterfaceToHostDataMap;

        struct RouterInterfaceData
        {
            IGMPv3 *owner;
            GroupToRouterDataMap groups;
            RouterState state;
            cMessage *generalQueryTimer;

            RouterInterfaceData(IGMPv3 *owner);
            virtual ~RouterInterfaceData();
        };
        typedef std::map<int, RouterInterfaceData*> InterfaceToRouterDataMap;


        enum IGMPTimerKind
        {
            IGMPV3_R_GENERAL_QUERY_TIMER,
            IGMPV3_R_GROUP_TIMER,
            IGMPV3_R_SOURCE_TIMER,
            IGMPV3_H_GENERAL_QUERY_TIMER,
            IGMPV3_H_GROUP_TIMER,
            IGMPV3_H_SOURCE_TIMER, // XXX unused?
        };

        // XXX delete this; use IGMPV3HostTimerSourceContext with empty sourceList
        struct IGMPV3HostTimerGroupContext
        {
            InterfaceEntry *ie;
            HostGroupData *hostGroup;
            IGMPV3HostTimerGroupContext(InterfaceEntry *ie, HostGroupData *hostGroup) : ie(ie), hostGroup(hostGroup) {}
        };

        struct IGMPV3HostTimerSourceContext
        {
            InterfaceEntry *ie;
            HostGroupData *hostGroup;
            IPv4AddressVector sourceList;
            IGMPV3HostTimerSourceContext(InterfaceEntry *ie, HostGroupData *hostGroup, const IPv4AddressVector &sourceList)
                : ie(ie), hostGroup(hostGroup), sourceList(sourceList) {}
        };

        struct IGMPV3HostGeneralTimerContext
        {
            InterfaceEntry *ie;
            HostInterfaceData *interfaceData;
            IGMPV3HostGeneralTimerContext(InterfaceEntry *ie, HostInterfaceData *interfaceData) : ie(ie), interfaceData(interfaceData) {}
        };

        struct IGMPV3RouterTimerContext
        {
            InterfaceEntry *ie;
            RouterGroupData *routerGroup;
            IGMPV3RouterTimerContext(InterfaceEntry *ie, RouterGroupData *routerGroup) : ie(ie), routerGroup(routerGroup) {}
        };

        struct IGMPV3RouterSourceTimerContext
        {
            InterfaceEntry *ie;
            RouterGroupData *routerGroup;
            IPv4Address sourceAddr;
            IGMPV3RouterSourceTimerContext(InterfaceEntry *ie, RouterGroupData *routerGroup, IPv4Address source)
                : ie(ie), routerGroup(routerGroup), sourceAddr(source) {}
        };

    protected:
        IRoutingTable *rt;
        IInterfaceTable *ift;
        NotificationBoard *nb;

        bool enabled;
        int robustness;
        double queryInterval;
        double queryResponseInterval;
        double groupMembershipInterval;
        double otherQuerierPresentInterval;
        double startupQueryInterval;
        double startupQueryCount;
        double lastMemberQueryInterval;
        double lastMemberQueryCount;
        double lastMemberQueryTime;
        double unsolicitedReportInterval;

        InterfaceToHostDataMap hostData;
        InterfaceToRouterDataMap routerData;

        int numGroups;
        int numHostGroups;
        int numRouterGroups;

        int numQueriesSent;
        int numQueriesRecv;
        int numGeneralQueriesSent;
        int numGeneralQueriesRecv;
        int numGroupSpecificQueriesSent;
        int numGroupSpecificQueriesRecv;
        int numGroupAndSourceSpecificQueriesSent;
        int numGroupAndSourceSpecificQueriesRecv;
        int numReportsSent;
        int numReportsRecv;

    protected:
        virtual int numInitStages() const {return NUM_INIT_STAGES;}
        virtual void initialize(int stage);
        virtual void handleMessage(cMessage *msg);
        virtual void receiveChangeNotification(int category, const cPolymorphic *details);
        virtual ~IGMPv3();

    protected:
        virtual HostInterfaceData *createHostInterfaceData();
        virtual RouterInterfaceData *createRouterInterfaceData();
        virtual HostGroupData *createHostGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual SourceRecord *createSourceRecord(InterfaceEntry *ie, IPv4Address group, IPv4Address source);
        virtual RouterGroupData *createRouterGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual HostInterfaceData *getHostInterfaceData(InterfaceEntry *ie);
        virtual RouterInterfaceData *getRouterInterfaceData(InterfaceEntry *ie);
        virtual HostGroupData *getHostGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual RouterGroupData *getRouterGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual SourceRecord *getSourceRecord(InterfaceEntry *ie, IPv4Address group, IPv4Address source);
        virtual void deleteHostInterfaceData(int interfaceId);
        virtual void deleteRouterInterfaceData(int interfaceId);
        virtual void deleteHostGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual void deleteRouterGroupData(InterfaceEntry *ie, IPv4Address group);
        virtual void deleteSourceRecord(InterfaceEntry *ie, IPv4Address group, IPv4Address source);

        virtual void configureInterface(InterfaceEntry *ie);

        virtual void startTimer(cMessage *timer, double interval);

        virtual void sendQuery(InterfaceEntry *ie, IPv4Address groupAddr, const IPv4AddressVector &sources, double maxRespTime);
        virtual void sendGroupReport(InterfaceEntry *ie, const std::vector<GroupRecord> &records);
        virtual void sendQueryToIP(IGMPv3Query *msg, InterfaceEntry *ie, IPv4Address dest);
        virtual void sendReportToIP(IGMPv3Report *msg, InterfaceEntry *ie, IPv4Address dest);

        virtual void processHostGeneralQueryTimer(cMessage *msg);
        virtual void processHostGroupQueryTimer(cMessage *msg);
        virtual void processRouterGeneralQueryTimer(cMessage *msg);
        virtual void processRouterGroupTimer(cMessage *msg);
        virtual void processRouterSourceTimer(cMessage *msg);

        virtual void processIgmpMessage(IGMPMessage *msg);
        virtual void processQuery(IGMPv3Query *msg);
        virtual void processReport(IGMPv3Report *msg);

        virtual void multicastSourceListChanged(InterfaceEntry *ie, IPv4Address group, const IPv4MulticastSourceList &sourceList);

        /**
         * Function for computing the time value in seconds from an encoded value.
         * Codes in the [1,127] interval are the number of 1/10 seconds,
         * codes above 127 are contain a 3-bit exponent and a four bit mantissa
         * and represents the (mantissa + 16) * 2^(3+exp) number of 1/10 seconds.
         */
        virtual double decodeTime(unsigned char code);
};




































#endif /* INET_IGMPV3_H */
