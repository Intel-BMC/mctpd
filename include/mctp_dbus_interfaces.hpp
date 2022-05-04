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

#include <libmctp.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <xyz/openbmc_project/Inventory/Decorator/LocationCode/server.hpp>

using endpointInterfaceMap =
    std::unordered_map<mctp_eid_t, std::shared_ptr<dbus_interface>>;

struct MsgTypes
{
    bool mctpControl = true;
    bool pldm = false;
    bool ncsi = false;
    bool ethernet = false;
    bool nvmeMgmtMsg = false;
    bool spdm = false;
    bool vdpci = false;
    bool vdiana = false;
};

struct EndpointProperties
{
    uint8_t endpointEid;
    std::string uuid;
    mctp_server::BindingModeTypes mode;
    uint16_t networkId;
    MsgTypes endpointMsgTypes;
    // Vendor PCI ID Support
    std::vector<uint16_t> vendorIdCapabilitySets;
    std::string vendorIdFormat;
    std::string locationCode;
};

class MCTPDBusInterfaces
{
  public:
    MCTPDBusInterfaces(std::shared_ptr<object_server>& objServer);
    MCTPDBusInterfaces() = delete;
    virtual ~MCTPDBusInterfaces();

    // Get own service name
    inline const std::string& getDbusName() const
    {
        return serviceName;
    }
    // Set own service name
    inline void setDbusName(const std::string& sName)
    {
        serviceName = sName;
    }

  protected:
    std::string serviceName = "xyz.openbmc_project.MCTP";
    std::shared_ptr<object_server> objectServer;
    std::shared_ptr<dbus_interface> mctpInterface;
    // vendor PCI Msg Interface
    endpointInterfaceMap vendorIdInterface;
    // Location code Interface
    endpointInterfaceMap locationCodeInterface;
    // binding-specific device property Interface
    endpointInterfaceMap deviceInterface;
    endpointInterfaceMap endpointInterface;
    endpointInterfaceMap msgTypeInterface;
    endpointInterfaceMap uuidInterface;

    virtual void
        populateDeviceProperties(const mctp_eid_t eid,
                                 const std::vector<uint8_t>& bindingPrivate);

    bool removeInterface(mctp_eid_t eid, endpointInterfaceMap& interfaces);
    void registerMsgTypes(std::shared_ptr<dbus_interface>& msgTypeIntf,
                          const MsgTypes& messageType);
    void populateEndpointProperties(const EndpointProperties& epProperties);
};
