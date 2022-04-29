/*
// Copyright (c) 2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include "utils/types.hpp"

#include <string>
#include <unordered_map>
#include <variant>

#include "libmctp-cmds.h"

using mctp_eid_t = uint8_t;

namespace mctpd
{
enum class EndPointType : uint8_t
{
    EndPoint = MCTP_ROUTING_ENTRY_ENDPOINT,
    BridgeAndEndPoints = MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS,
    BridgeOnly = MCTP_ROUTING_ENTRY_BRIDGE,
    BridgeWithoutEndpoint = MCTP_ROUTING_ENTRY_ENDPOINTS,
    Invalid,
};

EndPointType convertToEndpointType(const std::string& endpointType);

EndPointType convertToEndpointType(mctp_server::BindingModeTypes endpointType);

constexpr bool isBridge(EndPointType type)
{
    return type == EndPointType::BridgeAndEndPoints ||
           type == EndPointType::BridgeOnly ||
           type == EndPointType::BridgeWithoutEndpoint;
}

enum class PhysicalMediumIdentifier : uint8_t
{
    unspecified = 0,
    smbus20_100KHz = 1,
    smbus20AndI2C100kHz = 2,
    i2C100kHz = 3,
    smbus30orI2C400kHz = 4,
    smbus30orI2C1MHz = 5,
    pcie1_1 = 8,
    pcie2_0 = 9,
    pcie2_1 = 0xA,
    pcie3_0 = 0xB,
    pcie4_0 = 0xC,
    pcie5_0 = 0xD,
    i3c12_5Mhz = 0x30,
    i3c25Mhz = 0x31,
};

PhysicalMediumIdentifier convertToPhysicalMediumIdentifier(
    mctp_server::MctpPhysicalMediumIdentifiers medium);

class RoutingTable
{
  public:
    struct Entry
    {
        using MCTPLibData = get_routing_table_entry_with_address;
        inline Entry(mctp_eid_t eid, std::string service, EndPointType type,
                     uint8_t addrSize = 1) :
            serviceName(std::move(service))
        {
            routeEntry.routing_info.eid_range_size = 1; // Fixed for now
            routeEntry.routing_info.entry_type = static_cast<uint8_t>(type);
            routeEntry.routing_info.starting_eid = eid;
            routeEntry.routing_info.phys_address_size = addrSize;
        }
        constexpr bool isBridge() const
        {
            EndPointType type =
                static_cast<EndPointType>(routeEntry.routing_info.entry_type);
            return type == EndPointType::BridgeAndEndPoints ||
                   type == EndPointType::BridgeOnly ||
                   type == EndPointType::BridgeWithoutEndpoint;
        }
        MCTPLibData routeEntry{};
        // optional
        std::string serviceName{};
        bool isUpstream = false;
    };

    using EntryMap = std::unordered_map<mctp_eid_t, Entry>;

    const std::string& getServiceName(const mctp_eid_t eid) const;
    const EntryMap& getAllEntries() const noexcept;
    const Entry& getEntry(const mctp_eid_t eid) const;
    bool updateEntry(const mctp_eid_t eid, Entry entry);
    bool removeEntry(const mctp_eid_t eid);
    inline bool contains(mctp_eid_t eid)
    {
        return entries.count(eid) == 1;
    }

  private:
    EntryMap entries;
};

} // namespace mctpd
