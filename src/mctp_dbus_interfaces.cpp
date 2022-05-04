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

#include "mctp_dbus_interfaces.hpp"

using LocationCodeDecorator =
    sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::LocationCode;

MCTPDBusInterfaces::MCTPDBusInterfaces(
    std::shared_ptr<object_server>& objServer) :
    objectServer(objServer)
{
}

MCTPDBusInterfaces::~MCTPDBusInterfaces()
{
    for (auto& iter : endpointInterface)
    {
        objectServer->remove_interface(iter.second);
    }

    for (auto& iter : msgTypeInterface)
    {
        objectServer->remove_interface(iter.second);
    }

    for (auto& iter : uuidInterface)
    {
        objectServer->remove_interface(iter.second);
    }

    for (auto& iter : vendorIdInterface)
    {
        objectServer->remove_interface(iter.second);
    }
    for (auto& iter : locationCodeInterface)
    {
        objectServer->remove_interface(iter.second);
    }
    for (auto& iter : deviceInterface)
    {
        objectServer->remove_interface(iter.second);
    }

    objectServer->remove_interface(mctpInterface);
}

void MCTPDBusInterfaces::populateDeviceProperties(const mctp_eid_t,
                                                  const std::vector<uint8_t>&)
{
    // Do nothing
}

bool MCTPDBusInterfaces::removeInterface(mctp_eid_t eid,
                                         endpointInterfaceMap& interfaces)
{
    auto iter = interfaces.find(eid);
    if (iter != interfaces.end())
    {
        objectServer->remove_interface(iter->second);
        interfaces.erase(iter);
        return true;
    }
    return false;
}

void MCTPDBusInterfaces::registerMsgTypes(
    std::shared_ptr<dbus_interface>& msgTypeIntf, const MsgTypes& messageType)
{
    msgTypeIntf->register_property("MctpControl", messageType.mctpControl);
    msgTypeIntf->register_property("PLDM", messageType.pldm);
    msgTypeIntf->register_property("NCSI", messageType.ncsi);
    msgTypeIntf->register_property("Ethernet", messageType.ethernet);
    msgTypeIntf->register_property("NVMeMgmtMsg", messageType.nvmeMgmtMsg);
    msgTypeIntf->register_property("SPDM", messageType.spdm);
    msgTypeIntf->register_property("VDPCI", messageType.vdpci);
    msgTypeIntf->register_property("VDIANA", messageType.vdiana);
    msgTypeIntf->initialize();
}

void MCTPDBusInterfaces::populateEndpointProperties(
    const EndpointProperties& epProperties)
{
    std::string mctpDevObj = "/xyz/openbmc_project/mctp/device/";
    std::shared_ptr<dbus_interface> endpointIntf;
    std::string mctpEpObj =
        mctpDevObj + std::to_string(epProperties.endpointEid);

    // Endpoint interface
    endpointIntf =
        objectServer->add_interface(mctpEpObj, mctp_endpoint::interface);
    endpointIntf->register_property(
        "Mode",
        mctp_server::convertBindingModeTypesToString(epProperties.mode));
    endpointIntf->register_property("NetworkId", epProperties.networkId);
    endpointIntf->initialize();
    endpointInterface.emplace(epProperties.endpointEid,
                              std::move(endpointIntf));

    // UUID interface
    std::shared_ptr<dbus_interface> uuidIntf;
    uuidIntf = objectServer->add_interface(mctpEpObj,
                                           "xyz.openbmc_project.Common.UUID");
    uuidIntf->register_property("UUID", epProperties.uuid);
    uuidIntf->initialize();
    uuidInterface.emplace(epProperties.endpointEid, std::move(uuidIntf));

    // Vendor-defined message type interface
    if (epProperties.endpointMsgTypes.vdpci)
    {
        std::shared_ptr<dbus_interface> vendorIdIntf;
        vendorIdIntf = objectServer->add_interface(
            mctpEpObj, "xyz.openbmc_project.MCTP.PCIVendorDefined");
        vendorIdIntf->register_property("MessageTypeProperty",
                                        epProperties.vendorIdCapabilitySets);
        vendorIdIntf->register_property("VendorID",
                                        epProperties.vendorIdFormat);
        vendorIdIntf->initialize();
        vendorIdInterface.emplace(epProperties.endpointEid,
                                  std::move(vendorIdIntf));
    }

    // Location code interface
    std::shared_ptr<dbus_interface> locationCodeIntf;
    locationCodeIntf = objectServer->add_interface(
        mctpEpObj, LocationCodeDecorator::interface);
    locationCodeIntf->register_property("LocationCode",
                                        epProperties.locationCode);
    locationCodeIntf->initialize();
    locationCodeInterface.emplace(epProperties.endpointEid,
                                  std::move(locationCodeIntf));

    // Message type interface
    // This interface should be added last as adding it will trigger mctpwplus
    // deviceAdded event
    std::shared_ptr<dbus_interface> msgTypeIntf;
    msgTypeIntf =
        objectServer->add_interface(mctpEpObj, mctp_msg_types::interface);
    registerMsgTypes(msgTypeIntf, epProperties.endpointMsgTypes);
    msgTypeInterface.emplace(epProperties.endpointEid, std::move(msgTypeIntf));
}