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

#include "mctp_bridge.hpp"

#include "mctp_cmd_encoder.hpp"
#include "utils/utils.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

using RoutingTableEntry = mctpd::RoutingTable::Entry;

constexpr int completionCodeIndex = 3;
constexpr int noMoreSet = 0xFF;
static const std::string nullUUID = "00000000-0000-0000-0000-000000000000";

MCTPBridge::MCTPBridge(boost::asio::io_context& ioc,
                       std::shared_ptr<object_server>& objServer) :
    MCTPEndpoint(ioc, objServer)
{
}

bool MCTPBridge::getEidCtrlCmd(boost::asio::yield_context& yield,
                               const std::vector<uint8_t>& bindingPrivate,
                               const mctp_eid_t destEid,
                               std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ENDPOINT_ID>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get EID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get EID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_get_eid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Get EID failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("Get EID success");
    return true;
}

bool MCTPBridge::setEidCtrlCmd(boost::asio::yield_context& yield,
                               const std::vector<uint8_t>& bindingPrivate,
                               const mctp_eid_t destEid,
                               const mctp_ctrl_cmd_set_eid_op operation,
                               mctp_eid_t eid, std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_SET_ENDPOINT_ID>(req, operation, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Set EID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Set EID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_set_eid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Set EID failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("Set EID success");
    return true;
}

bool MCTPBridge::getUuidCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid,
                                std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ENDPOINT_UUID>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_get_uuid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID failed");
        return false;
    }

    const std::string nilUUID = "00000000-0000-0000-0000-000000000000";
    mctp_ctrl_resp_get_uuid* getUUIDRespPtr =
        reinterpret_cast<mctp_ctrl_resp_get_uuid*>(resp.data());
    std::string uuidResp = formatUUID(getUUIDRespPtr->uuid);
    if (nilUUID == uuidResp)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get UUID: Device returned Nil UUID");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Get UUID success: " + uuidResp).c_str());
    return true;
}

bool MCTPBridge::getMsgTypeSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    MsgTypeSupportCtrlResp* msgTypeSupportResp)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response");
        return false;
    }

    const size_t minMsgTypeRespLen = 5;
    uint8_t completionCode = resp[completionCodeIndex];
    if (completionCode != MCTP_CTRL_CC_SUCCESS ||
        resp.size() <= minMsgTypeRespLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response",
            phosphor::logging::entry("CC=0x%02X", completionCode),
            phosphor::logging::entry("LEN=0x%02X", resp.size()));

        std::vector<uint8_t> respHeader =
            std::vector<uint8_t>(resp.begin(), resp.begin() + minCmdRespSize);
        std::copy(
            respHeader.begin(), respHeader.end(),
            reinterpret_cast<uint8_t*>(&msgTypeSupportResp->ctrlMsgHeader));
        msgTypeSupportResp->completionCode = completionCode;
        return false;
    }

    std::copy_n(resp.begin(), minMsgTypeRespLen,
                reinterpret_cast<uint8_t*>(msgTypeSupportResp));
    if ((resp.size() - minMsgTypeRespLen) != msgTypeSupportResp->msgTypeCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response length");
        return false;
    }

    msgTypeSupportResp->msgType.assign(resp.begin() + minMsgTypeRespLen,
                                       resp.end());

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get Message Type Support success");
    return true;
}

bool MCTPBridge::getMctpVersionSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    const uint8_t msgTypeNo,
    MctpVersionSupportCtrlResp* mctpVersionSupportCtrlResp)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_VERSION_SUPPORT>(req, msgTypeNo))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get MCTP Version Support: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response");
        return false;
    }

    const size_t minMsgTypeRespLen = 5;
    const size_t mctpVersionLen = 4;
    uint8_t completionCode = resp[completionCodeIndex];
    if (completionCode != MCTP_CTRL_CC_SUCCESS ||
        resp.size() <= minMsgTypeRespLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response",
            phosphor::logging::entry("CC=0x%02X", completionCode),
            phosphor::logging::entry("LEN=0x%02X", resp.size()));

        std::vector<uint8_t> respHeader =
            std::vector<uint8_t>(resp.begin(), resp.begin() + minCmdRespSize);
        std::copy(respHeader.begin(), respHeader.end(),
                  reinterpret_cast<uint8_t*>(
                      &mctpVersionSupportCtrlResp->ctrlMsgHeader));
        mctpVersionSupportCtrlResp->completionCode = completionCode;
        return false;
    }

    std::copy_n(resp.begin(), minMsgTypeRespLen,
                reinterpret_cast<uint8_t*>(mctpVersionSupportCtrlResp));
    if ((resp.size() - minMsgTypeRespLen) !=
        mctpVersionSupportCtrlResp->verNoEntryCount * mctpVersionLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response length");
        return false;
    }

    for (size_t iter = 1; iter <= mctpVersionSupportCtrlResp->verNoEntryCount;
         iter++)
    {
        size_t verNoEntryStartOffset =
            minMsgTypeRespLen + (mctpVersionLen * (iter - 1));
        struct MCTPVersionFields versionData = {};
        versionData.major = resp[verNoEntryStartOffset];
        versionData.minor = resp[verNoEntryStartOffset + 1];
        versionData.update = resp[verNoEntryStartOffset + 2];
        versionData.alpha = resp[verNoEntryStartOffset + 3];
        mctpVersionSupportCtrlResp->verNoEntry.push_back(
            std::move(versionData));
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get MCTP Version Support success");
    return true;
}

bool MCTPBridge::getPCIVDMessageSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    std::vector<uint16_t>& vendorSetIdList, std::string& venFormatData)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "getPCIVendorIdMessageSupportCtrlCmd called...");
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};
    uint8_t vendorIdSet = 0;
    venFormatData.clear();
    // local structure to receive the vendor ID response
    MctpVendIdMsgSupportResp pciVendIdMsgSupportResp;
    // cannot be sure of the count, so processing from 0 ~ 255
    while (vendorIdSet < 255)
    {
        // format the data as per the request msg format
        if (!getFormattedReq<MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT>(
                req, vendorIdSet))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Request formatting failed");
            return false;
        }

        if (PacketState::receivedResponse !=
            sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: sending & receiving failed");
            return false;
        }

        // total resp size(including ctrl header) '10'
        // ctrlheader  Compl.Code  VendIdSet  VendIdFmt  VendorFrmtData
        // vendIdSetType
        //     3           1          1          1             2             2
        //     (bytes)
        const ssize_t pciVDMessageSupportCmdRespSize =
            sizeof(MctpVendIdMsgSupportResp);

        if (!checkMinRespSize(resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Invalid Response Length");
            return false;
        }

        // assuming 1st byte after ctrl header is completion code index
        uint8_t completionCode = resp[completionCodeIndex];
        if ((completionCode != MCTP_CTRL_CC_SUCCESS) ||
            (resp.size() < pciVDMessageSupportCmdRespSize))
        {

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Invalid response",
                phosphor::logging::entry("CC=0x%02X", completionCode),
                phosphor::logging::entry("LEN=0x%02X", resp.size()));
            return false;
        }

        pciVendIdMsgSupportResp = {};

        // copy the response onto local structure
        std::copy_n(resp.begin(), pciVDMessageSupportCmdRespSize,
                    reinterpret_cast<uint8_t*>(&pciVendIdMsgSupportResp));

        uint16_t venid = htobe16(pciVendIdMsgSupportResp.vendorIdFormatData);
        std::stringstream op_str;
        op_str << std::hex << venid;
        venFormatData = op_str.str();

        vendorSetIdList.push_back(
            htobe16(pciVendIdMsgSupportResp.vendorIdSetCmdType));

        if (pciVendIdMsgSupportResp.vendorIdSet == noMoreSet)
        {
            // break the loop once 0xFF is found in set.
            vendorIdSet = 0;
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Vendor Id Set-Selector loop Break");
            break;
        }
        vendorIdSet++;
        if (vendorIdSet == 255 &&
            pciVendIdMsgSupportResp.vendorIdSet != noMoreSet)
        { // invalid scenario iteration
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid vendor ID set iteration");
            return false;
        }
    }
    return true;
}

bool MCTPBridge::getRoutingTableCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    uint8_t entryHandle, std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES>(req,
                                                                  entryHandle))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response length");
        return false;
    }

    uint8_t* respPtr = resp.data();
    if (*(respPtr + sizeof(mctp_ctrl_msg_hdr)) != MCTP_CTRL_CC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Unsuccessful completion code");
        return false;
    }

    if (resp.size() < sizeof(mctp_ctrl_resp_get_routing_table))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Response length is too short: Cannot "
            "read number of entries",
            phosphor::logging::entry("LEN=%d", resp.size()));
        return false;
    }

    mctp_ctrl_resp_get_routing_table* routingTableHdr =
        reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(resp.data());
    size_t entryOffset = sizeof(mctp_ctrl_resp_get_routing_table);
    for (uint8_t i = 0; i < routingTableHdr->number_of_entries; i++)
    {
        get_routing_table_entry* routingTableEntry =
            reinterpret_cast<get_routing_table_entry*>(resp.data() +
                                                       entryOffset);
        entryOffset += sizeof(get_routing_table_entry);
        if (resp.size() < entryOffset)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get Routing Table Entry: Response length is too short: Cannot "
                "read routing table entry",
                phosphor::logging::entry("LEN=%d", resp.size()));
            return false;
        }

        entryOffset += routingTableEntry->phys_address_size;
        if (resp.size() < entryOffset)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get Routing Table Entry: Response length is too short: Cannot "
                "read physical address",
                phosphor::logging::entry("LEN=%d", resp.size()));
            return false;
        }
    }

    if (resp.size() != entryOffset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Invalid response length",
            phosphor::logging::entry("LEN=%d", resp.size()),
            phosphor::logging::entry("EXPECTED_LEN=%d", entryOffset));
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get Routing Table Entry success");
    return true;
}

void MCTPBridge::logUnsupportedMCTPVersion(
    const std::vector<struct MCTPVersionFields> versionsData,
    const mctp_eid_t eid)
{
    static std::vector<mctp_eid_t> incompatibleEIDs;

    if (find(incompatibleEIDs.begin(), incompatibleEIDs.end(), eid) !=
        incompatibleEIDs.end())
    {
        return;
    }

    auto versionIter =
        std::find_if(versionsData.begin(), versionsData.end(),
                     [this](const auto& versionEntry) {
                         return isMCTPVersionSupported(versionEntry);
                     });

    if (versionIter != versionsData.end())
    {
        return;
    }

    phosphor::logging::log<phosphor::logging::level::WARNING>(
        ("Get MCTP version support command returned unsupported version for "
         "EID " +
         std::to_string(eid))
            .c_str());

    incompatibleEIDs.push_back(eid);
}

static std::optional<mctp_eid_t> checkEIDMismatchAndGetEID(mctp_eid_t eid,
                                                           mctp_eid_t destEID)
{
    if (eid != destEID && eid != MCTP_EID_NULL && destEID != MCTP_EID_NULL)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "EID mismatch detected", phosphor::logging::entry("EID=%d", eid),
            phosphor::logging::entry("EID_REPORTED=%d", destEID));
        return std::nullopt;
    }
    if (eid == MCTP_EID_NULL)
    {
        eid = destEID;
    }
    return eid;
}

std::optional<mctp_eid_t> MCTPBridge::busOwnerRegisterEndpoint(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, mctp_eid_t eid)
{
    MctpVersionSupportCtrlResp getMctpControlVersion = {};
    if (!(getMctpVersionSupportCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL,
                                       MCTP_MESSAGE_TYPE_MCTP_CTRL,
                                       &getMctpControlVersion)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get MCTP Control Version failed");
        return std::nullopt;
    }

    // TODO: Validate MCTP Control message version supported

    std::vector<uint8_t> getEidResp = {};
    if (!(getEidCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL, getEidResp)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get EID failed");
        return std::nullopt;
    }
    const mctp_ctrl_resp_get_eid* getEidRespPtr =
        reinterpret_cast<mctp_ctrl_resp_get_eid*>(getEidResp.data());
    std::optional<mctp_eid_t> destEID =
        checkEIDMismatchAndGetEID(eid, getEidRespPtr->eid);
    if (!destEID.has_value())
    {
        return std::nullopt;
    }
    eid = destEID.value();

    logUnsupportedMCTPVersion(getMctpControlVersion.verNoEntry, eid);

    std::vector<uint8_t> getUuidResp = {};
    if (!(getUuidCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL, getUuidResp)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get UUID failed");
        if (isEIDRegistered(getEidRespPtr->eid))
        {
            return getEidRespPtr->eid;
        }

        if (eid != MCTP_EID_NULL)
        {
            unregisterEndpoint(eid);
        }

        // In case EP doesn't support Get UUID set to all 0. This results in
        // nullUUID
        getUuidResp.resize(sizeof(mctp_ctrl_resp_get_uuid), 0);
    }

    const mctp_ctrl_resp_get_uuid* getUuidRespPtr =
        reinterpret_cast<mctp_ctrl_resp_get_uuid*>(getUuidResp.data());
    std::string destUUID = formatUUID(getUuidRespPtr->uuid);
    if (isEIDMappedToUUID(getEidRespPtr->eid, destUUID))
    {
        return getEidRespPtr->eid;
    }
    if (auto uuidMappedEID = getEIDForReregistration(destUUID))
    {
        eid = uuidMappedEID.value();
    }

    if (!deviceWatcher.checkDeviceInitThreshold(bindingPrivate))
    {
        return std::nullopt;
    }

    if (eid == MCTP_EID_NULL)
    {
        try
        {
            eid = eidPool.getAvailableEidFromPool();
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }

    // TODO: Routing table construction
    // TODO: Assigne pool of EID if the endpoint is a bridge
    // TODO: Take care of EIDs(Static EID) which are not owned by us

    // Set EID
    std::vector<uint8_t> setEidResp = {};
    if (!(setEidCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL, set_eid, eid,
                        setEidResp)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Set EID failed");
        eidPool.updateEidStatus(eid, false);
        return std::nullopt;
    }
    mctp_ctrl_resp_set_eid* setEidRespPtr =
        reinterpret_cast<mctp_ctrl_resp_set_eid*>(setEidResp.data());
    if (eid != setEidRespPtr->eid_set)
    {
        // TODO: Force setEID if needed
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Set EID failed. Reported different EID in the response.");
        eidPool.updateEidStatus(eid, false);
        return std::nullopt;
    }
    eidPool.updateEidStatus(eid, true);

    // Get Message Type Support
    MsgTypeSupportCtrlResp msgTypeSupportResp;
    if (!(getMsgTypeSupportCtrlCmd(yield, bindingPrivate, eid,
                                   &msgTypeSupportResp)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get Message Type Support failed");
        return std::nullopt;
    }

    // check if EID is already registered
    if (endpointInterface.find(eid) != endpointInterface.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("EID " + std::to_string(eid) + " is already registered").c_str());
        return std::nullopt;
    }

    // Expose interface as per the result
    EndpointProperties epProperties;
    epProperties.endpointEid = eid;
    epProperties.uuid = destUUID;
    try
    {
        epProperties.mode = getEndpointType(getEidRespPtr->eid_type);
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
    // Network ID need to be assigned only if EP is requesting for the same.
    // Keep Network ID as zero and update it later if a change happend.
    epProperties.networkId = 0x00;
    epProperties.endpointMsgTypes = getMsgTypes(msgTypeSupportResp.msgType);
    getVendorDefinedMessageTypes(yield, bindingPrivate, eid, epProperties);
    epProperties.locationCode = getLocationCode(bindingPrivate).value_or("");

    populateDeviceProperties(eid, bindingPrivate);
    populateEndpointProperties(epProperties);

    // Pass eid, service name & Type.
    auto endpointType = mctpd::convertToEndpointType(epProperties.mode);
    mctpd::RoutingTable::Entry entry(eid, getDbusName(), endpointType);
    entry.routeEntry.routing_info.phys_media_type_id = static_cast<uint8_t>(
        mctpd::convertToPhysicalMediumIdentifier(bindingMediumID));
    updateRoutingTableEntry(entry, bindingPrivate);
    if (mctpd::isBridge(endpointType))
    {
        sendRoutingTableEntriesToBridge(eid, bindingPrivate);
    }

    // Update the uuidTable with eid and the uuid of the endpoint registered.
    if (destUUID != nullUUID && eid != MCTP_EID_NULL)
    {
        uuidTable.insert_or_assign(eid, destUUID);
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Device Registered: EID = " + std::to_string(eid)).c_str());
    return eid;
}

void MCTPBridge::getVendorDefinedMessageTypes(
    boost::asio::yield_context yield,
    const std::vector<uint8_t>& bindingPrivate, mctp_eid_t destEid,
    EndpointProperties& epProperties)
{
    if (epProperties.endpointMsgTypes.vdpci)
    {
        std::vector<uint16_t> vendorSetIdList = {};
        std::string vendorFormat;
        if (!getPCIVDMessageSupportCtrlCmd(yield, bindingPrivate, destEid,
                                           vendorSetIdList, vendorFormat))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get Vendor Id Support failed");
            /*
              If this command fails, still go ahead with endpoint
              registration since this is an optional command
            */
            epProperties.vendorIdFormat = "0x0";
            epProperties.vendorIdCapabilitySets = {};
            return;
        }
        epProperties.vendorIdCapabilitySets.assign(vendorSetIdList.begin(),
                                                   vendorSetIdList.end());

        epProperties.vendorIdFormat = "0x";
        epProperties.vendorIdFormat.append(vendorFormat);
    }
}

static std::vector<uint8_t> formatRoutingInfoUpdateCommand(
    std::vector<RoutingTableEntry::MCTPLibData>& entries)
{
    std::vector<uint8_t> req;
    req.resize(sizeof(mctp_ctrl_cmd_routing_info_update) +
               sizeof(get_routing_table_entry_with_address) * entries.size());

    auto routingInfoUpdate =
        reinterpret_cast<mctp_ctrl_cmd_routing_info_update*>(req.data());

    size_t formattedSize = 0;
    if (!mctp_encode_ctrl_cmd_routing_information_update(
            routingInfoUpdate, getRqDgramInst(), entries.data(),
            static_cast<uint8_t>(entries.size()), &formattedSize))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Routing info update. Encode error from lib");
        formattedSize = 0;
    }
    req.resize(formattedSize);

    return req;
}

void MCTPBridge::sendRoutingTableEntries(
    const std::vector<RoutingTableEntry::MCTPLibData>& entries,
    std::optional<std::vector<uint8_t>> bindingPrivateData,
    const mctp_eid_t eid)
{
    boost::asio::spawn([entries = entries, eid, bindingPrivateData,
                        this](boost::asio::yield_context yield) mutable {
        std::vector<uint8_t> req = formatRoutingInfoUpdateCommand(entries);
        std::vector<uint8_t> resp;

        if (!bindingPrivateData)
        {
            // TODO Introduce a helper to check if a given binding requires
            // binding private data or not, and call getBindingPrivateData only
            // if the binding requires
            bindingPrivateData = getBindingPrivateData(eid);
            if (!bindingPrivateData)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "RoutingInfoUpdate: Unable to find EID");
                return;
            }
        }

        if (PacketState::receivedResponse !=
            sendAndRcvMctpCtrl(yield, req, eid, bindingPrivateData.value(),
                               resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "RoutingInfoUpdate: Unable to get response");
            return;
        }

        if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_routing_info_update>(
                resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "RoutingInfoUpdate: Unsuccesful response received");
        }
    });
}

void MCTPBridge::sendNewRoutingTableEntryToAllBridges(
    const mctpd::RoutingTable::Entry& entry)
{
    std::vector<RoutingTableEntry::MCTPLibData> libmctpEntries{
        entry.routeEntry};

    auto& entries = this->routingTable.getAllEntries();
    for (const auto& [eid, val] : entries)
    {
        // Send only to downstream bridges
        if (val.isBridge() &&
            (eid != entry.routeEntry.routing_info.starting_eid) &&
            !val.isUpstream)
        {
            sendRoutingTableEntries(libmctpEntries, std::nullopt, eid);
        }
    }
}

void MCTPBridge::sendRoutingTableEntriesToBridge(
    const mctp_eid_t bridge, const std::vector<uint8_t>& bindingPrivate)
{
    auto& routingTableEntries = this->routingTable.getAllEntries();
    std::vector<RoutingTableEntry::MCTPLibData> libmctpEntries;
    for (const auto& entry : routingTableEntries)
    {
        libmctpEntries.emplace_back(entry.second.routeEntry);
    }
    sendRoutingTableEntries(libmctpEntries, bindingPrivate, bridge);
}