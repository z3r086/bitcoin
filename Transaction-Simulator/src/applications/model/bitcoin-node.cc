/**
 * This file contains the definitions of the functions declared in bitcoin-node.h
 */

#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "bitcoin-node.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BitcoinNode");

NS_OBJECT_ENSURE_REGISTERED (BitcoinNode);

TypeId
BitcoinNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::BitcoinNode")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<BitcoinNode> ()
    .AddAttribute ("Local",
                   "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&BitcoinNode::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("Protocol",
                   "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (UdpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&BitcoinNode::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("InvTimeoutMinutes",
				   "The timeout of inv messages in minutes",
                   TimeValue (Minutes (20)),
                   MakeTimeAccessor (&BitcoinNode::m_invTimeoutMinutes),
                   MakeTimeChecker())
    .AddTraceSource ("Rx",
                     "A packet has been received",
                     MakeTraceSourceAccessor (&BitcoinNode::m_rxTrace),
                     "ns3::Packet::AddressTracedCallback")
  ;
  return tid;
}

BitcoinNode::BitcoinNode (void) : m_bitcoinPort (8333), m_secondsPerMin(60), m_countBytes (4), m_bitcoinMessageHeader (90),
                                  m_inventorySizeBytes (36), m_getHeadersSizeBytes (72), m_headersSizeBytes (81),
                                  m_averageTransactionSize (522.4), m_transactionIndexSize (2), m_txToCreate(0), m_blocksOnly(false)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_numberOfPeers = m_peersAddresses.size();
}

BitcoinNode::~BitcoinNode(void)
{
  NS_LOG_FUNCTION (this);
}

Ptr<Socket>
BitcoinNode::GetListeningSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socket;
}


std::vector<Ipv4Address>
BitcoinNode::GetPeersAddresses (void) const
{
  NS_LOG_FUNCTION (this);
  return m_peersAddresses;
}


void
BitcoinNode::SetPeersAddresses (const std::vector<Ipv4Address> &peers)
{
  NS_LOG_FUNCTION (this);
  m_peersAddresses = peers;
  m_numberOfPeers = m_peersAddresses.size();
}


void
BitcoinNode::SetPeersDownloadSpeeds (const std::map<Ipv4Address, double> &peersDownloadSpeeds)
{
  NS_LOG_FUNCTION (this);
  m_peersDownloadSpeeds = peersDownloadSpeeds;
}


void
BitcoinNode::SetPeersUploadSpeeds (const std::map<Ipv4Address, double> &peersUploadSpeeds)
{
  NS_LOG_FUNCTION (this);
  m_peersUploadSpeeds = peersUploadSpeeds;
}

void
BitcoinNode::SetNodeInternetSpeeds (const nodeInternetSpeeds &internetSpeeds)
{
  NS_LOG_FUNCTION (this);

  m_downloadSpeed = internetSpeeds.downloadSpeed * 1000000 / 8 ;
  m_uploadSpeed = internetSpeeds.uploadSpeed * 1000000 / 8 ;
}


void
BitcoinNode::SetNodeStats (nodeStatistics *nodeStats)
{
  NS_LOG_FUNCTION (this);
  m_nodeStats = nodeStats;
}

void
BitcoinNode::SetProperties (uint64_t txToCreate)
{
  NS_LOG_FUNCTION (this);
  m_txToCreate = txToCreate;
}

void
BitcoinNode::SetProtocolType (enum ProtocolType protocolType)
{
  NS_LOG_FUNCTION (this);
  m_protocolType = protocolType;
}


void
BitcoinNode::SetMode (bool blocksOnly)
{
  m_blocksOnly = blocksOnly;
}

void
BitcoinNode::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;

  // chain up
  Application::DoDispose ();
}


// Application Methods
void
BitcoinNode::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already

  srand(time(NULL) + GetNode()->GetId());
  NS_LOG_INFO ("Node " << GetNode()->GetId() << ": download speed = " << m_downloadSpeed << " B/s");
  NS_LOG_INFO ("Node " << GetNode()->GetId() << ": upload speed = " << m_uploadSpeed << " B/s");
  NS_LOG_INFO ("Node " << GetNode()->GetId() << ": m_numberOfPeers = " << m_numberOfPeers);
  NS_LOG_INFO ("Node " << GetNode()->GetId() << ": m_invTimeoutMinutes = " << m_invTimeoutMinutes.GetMinutes() << "mins");
  NS_LOG_WARN ("Node " << GetNode()->GetId() << ": m_protocolType = " << getProtocolType(m_protocolType));

  NS_LOG_INFO ("Node " << GetNode()->GetId() << ": My peers are");

  for (auto it = m_peersAddresses.begin(); it != m_peersAddresses.end(); it++)
    NS_LOG_INFO("\t" << *it);

  double currentMax = 0;

  for(auto it = m_peersDownloadSpeeds.begin(); it != m_peersDownloadSpeeds.end(); ++it )
  {
    //std::cout << "Node " << GetNode()->GetId() << ": peer " << it->first << "download speed = " << it->second << " Mbps" << std::endl;
  }

  if (!m_socket)
  {
    m_socket = Socket::CreateSocket (GetNode (), m_tid);
    m_socket->Bind (m_local);
    m_socket->Listen ();
    m_socket->ShutdownSend ();
    if (addressUtils::IsMulticast (m_local))
    {
      Ptr<UdpSocket> udpSocket = DynamicCast<UdpSocket> (m_socket);
      if (udpSocket)
      {
        // equivalent to setsockopt (MCAST_JOIN_GROUP)
        udpSocket->MulticastJoinGroup (0, m_local);
      }
      else
      {
        NS_FATAL_ERROR ("Error: joining multicast on a non-UDP socket");
      }
    }
  }

  m_socket->SetRecvCallback (MakeCallback (&BitcoinNode::HandleRead, this));
  m_socket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&BitcoinNode::HandleAccept, this));
  m_socket->SetCloseCallbacks (
    MakeCallback (&BitcoinNode::HandlePeerClose, this),
    MakeCallback (&BitcoinNode::HandlePeerError, this));

  NS_LOG_DEBUG ("Node " << GetNode()->GetId() << ": Before creating sockets");
  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i)
  {
    m_peersSockets[*i] = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
    m_peersSockets[*i]->Connect (InetSocketAddress (*i, m_bitcoinPort));
  }
  NS_LOG_DEBUG ("Node " << GetNode()->GetId() << ": After creating sockets");

  m_nodeStats->nodeId = GetNode ()->GetId ();
  m_nodeStats->invReceivedMessages = 0;
  m_nodeStats->invSentMessages = 0;
  m_nodeStats->invReceivedBytes = 0;
  m_nodeStats->invSentBytes = 0;
  m_nodeStats->getDataReceivedMessages = 0;
  m_nodeStats->getDataSentMessages = 0;
  m_nodeStats->getDataReceivedBytes = 0;
  m_nodeStats->getDataSentBytes = 0;
  m_nodeStats->txCreated = 0;
  m_nodeStats->connections = m_peersAddresses.size();

  m_nodeStats->blocksOnly = m_blocksOnly;

  // if (m_protocolType == FILTERS_ON_LINKS) {
  //   AnnounceFilters();
  // }
  AnnounceMode();
}

void
BitcoinNode::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);

  for (std::vector<Ipv4Address>::iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i) //close the outgoing sockets
  {
    m_peersSockets[*i]->Close ();
  }


  if (m_socket)
  {
    m_socket->Close ();
    m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  }

  NS_LOG_WARN ("\n\nBITCOIN NODE " << GetNode ()->GetId () << ":");
}

void
BitcoinNode::AnnounceFilters (void)
{
  int count = 0;
  const uint8_t delimiter[] = "#";

  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i)
  {
    rapidjson::Document filterData;

    rapidjson::Value value;
    value = FILTER;
    filterData.SetObject();

    filterData.AddMember("message", value, filterData.GetAllocator());

    rapidjson::Value filterValue;
    filterValue.SetInt(count++ % 8);


    filterData.AddMember("filter", filterValue, filterData.GetAllocator());


    rapidjson::StringBuffer filterInfo;
    rapidjson::Writer<rapidjson::StringBuffer> filterWriter(filterInfo);
    filterData.Accept(filterWriter);

    m_peersSockets[*i]->Send (reinterpret_cast<const uint8_t*>(filterInfo.GetString()), filterInfo.GetSize(), 0);
    m_peersSockets[*i]->Send(delimiter, 1, 0);
  }
}

void
BitcoinNode::AnnounceMode (void)
{
  int count = 0;
  const uint8_t delimiter[] = "#";

  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i)
  {
    rapidjson::Document modeData;

    rapidjson::Value value;
    value = MODE;
    modeData.SetObject();

    modeData.AddMember("message", value, modeData.GetAllocator());

    rapidjson::Value modeValue;
    modeValue.SetBool(m_blocksOnly);


    modeData.AddMember("mode", modeValue, modeData.GetAllocator());


    rapidjson::StringBuffer modeInfo;
    rapidjson::Writer<rapidjson::StringBuffer> modeWriter(modeInfo);
    modeData.Accept(modeWriter);

    m_peersSockets[*i]->Send (reinterpret_cast<const uint8_t*>(modeInfo.GetString()), modeInfo.GetSize(), 0);
    m_peersSockets[*i]->Send(delimiter, 1, 0);

  }

  Simulator::Schedule (Seconds(100), &BitcoinNode::ScheduleNextTransactionEvent, this);
  // Simulator::Schedule (Seconds(100), &BitcoinNode::ScheduleNextBlockEvent, this);

}




void
BitcoinNode::ScheduleNextTransactionEvent (void)
{
  NS_LOG_FUNCTION (this);

  // TODO Fix
  if (m_fixedTxTimeGeneration == 0)
    m_fixedTxTimeGeneration = 100;

  if (m_txToCreate == 0)
    return;


  uint m_nextTxTime = m_fixedTxTimeGeneration;

  NS_LOG_DEBUG ("Time " << Simulator::Now ().GetSeconds () << ": Node " << GetNode ()->GetId ()
              << " fixed Tx Time Generation " << m_fixedTxTimeGeneration << "s");
  EventId m_nextTransactionEvent = Simulator::Schedule (Seconds(m_fixedTxTimeGeneration), &BitcoinNode::EmitTransaction, this);
}


void
BitcoinNode::ScheduleNextBlockEvent (void)
{
  int fixedBlockTimeGeneration = 60*100;
  Simulator::Schedule (Seconds(fixedBlockTimeGeneration), &BitcoinNode::EmitBlock, this);
}

void
BitcoinNode::EmitBlock (void)
{
  rapidjson::Document blockData;

  rapidjson::Value value;
  value = BLOCK;
  blockData.SetObject();

  blockData.AddMember("message", value, blockData.GetAllocator());

  rapidjson::Value blockValue;
  blockValue.SetInt(1);


  blockData.AddMember("block", blockValue, blockData.GetAllocator());


  rapidjson::StringBuffer blockInfo;
  rapidjson::Writer<rapidjson::StringBuffer> blockWriter(blockInfo);
  blockData.Accept(blockWriter);

  const uint8_t delimiter[] = "#";

  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i)
  {
    if (!blocksOnlyMode[*i])
      continue;

    // Block is 1MB
    int blockSize = 1024 * 1024;
    m_peersSockets[*i]->Send (reinterpret_cast<const uint8_t*>(blockInfo.GetString()), blockSize, 0);
    m_peersSockets[*i]->Send(delimiter, 1, 0);
  }

  m_nodeStats->blocksRelayed+=1;

  ScheduleNextBlockEvent();
}


void
BitcoinNode::EmitTransaction (void)
{
  NS_LOG_FUNCTION (this);
  rapidjson::Document inv;
  rapidjson::Document tx;

  int nodeId = GetNode ()->GetId ();
  double currentTime = Simulator::Now ().GetSeconds ();
  std::ostringstream stringStream;
  std::string transactionHash;

  stringStream << currentTime << "/" << nodeId << "/" << m_nodeStats->txCreated++;
  transactionHash = stringStream.str();

  inv.SetObject();
  tx.SetObject();

  std::cout << "Emitting Tx: " <<  transactionHash << "\n";

  Transaction newTx (currentTime, currentTime, Ipv4Address("127.0.0.1"));


  rapidjson::Value value;
  rapidjson::Value array(rapidjson::kArrayType);
  rapidjson::Value transactionInfo(rapidjson::kObjectType);

  value.SetString("tx");
  inv.AddMember("type", value, inv.GetAllocator());

  value = INV;
  inv.AddMember("message", value, inv.GetAllocator());

  value.SetString(transactionHash.c_str(), transactionHash.size(), inv.GetAllocator());
  array.PushBack(value, inv.GetAllocator());

  inv.AddMember("inv", array, inv.GetAllocator());


  rapidjson::StringBuffer invInfo;
  rapidjson::Writer<rapidjson::StringBuffer> invWriter(invInfo);
  inv.Accept(invWriter);


  rapidjson::StringBuffer txInfo;
  rapidjson::Writer<rapidjson::StringBuffer> txWriter(txInfo);

  int count = 0;

  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i, ++count)
  {


    const uint8_t delimiter[] = "#";
    m_peersSockets[*i]->Send (reinterpret_cast<const uint8_t*>(invInfo.GetString()), invInfo.GetSize(), 0);
    m_peersSockets[*i]->Send (delimiter, 1, 0);

    // to track tx gen time
    m_nodeStats->txReceivedTimes[transactionHash] = Simulator::Now().GetSeconds();


    NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                 << "s node " << GetNode ()->GetId ()
                 << " sent a packet " << invInfo.GetString()
	         << " to " << *i);

        m_nodeStats->invSentMessages += 1;

  }

  if (m_nodeStats->txCreated >= m_txToCreate)
    return;

  ScheduleNextTransactionEvent ();
}


void
BitcoinNode::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  Address from;

  std::cout << "Handling read: " <<  "\n";

  while ((packet = socket->RecvFrom (from)))
  {
      if (packet->GetSize () == 0)
      { //EOF
         break;
      }

      if (InetSocketAddress::IsMatchingType (from))
      {
        /**
         * We may receive more than one packets simultaneously on the socket,
         * so we have to parse each one of them.
         */
        std::string delimiter = "#";
        std::string parsedPacket;
        size_t pos = 0;
        char *packetInfo = new char[packet->GetSize () + 1];
        std::ostringstream totalStream;

        packet->CopyData (reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize ());
        packetInfo[packet->GetSize ()] = '\0'; // ensure that it is null terminated to avoid bugs

        /**
         * Add the buffered data to complete the packet
         */
        totalStream << m_bufferedData[from] << packetInfo;
        std::string totalReceivedData(totalStream.str());
        NS_LOG_INFO("Node " << GetNode ()->GetId () << " Total Received Data: " << totalReceivedData);

        while ((pos = totalReceivedData.find(delimiter)) != std::string::npos)
        {
          parsedPacket = totalReceivedData.substr(0, pos);
          NS_LOG_INFO("Node " << GetNode ()->GetId () << " Parsed Packet: " << parsedPacket);

          rapidjson::Document d;
          d.Parse(parsedPacket.c_str());

          if(!d.IsObject())
          {
            NS_LOG_WARN("The parsed packet is corrupted");
            totalReceivedData.erase(0, pos + delimiter.length());
            continue;
          }

          rapidjson::StringBuffer buffer;
          rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
          d.Accept(writer);

          NS_LOG_INFO ("At time "  << Simulator::Now ().GetSeconds ()
                        << "s bitcoin node " << GetNode ()->GetId () << " received "
                        <<  packet->GetSize () << " bytes from "
                        << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                        << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                        << " with info = " << buffer.GetString());


          switch (d["message"].GetInt())
          {
            case FILTER:
            {
              uint32_t filter = d["filter"].GetInt();
              filters[from] = filter;
              break;
            }
            case MODE:
            {
              bool blocksOnly = d["mode"].GetBool();
              blocksOnlyMode[from] = blocksOnly;
              break;
            }
            case BLOCK:
            {
              bool blocksOnly = d["block"].GetInt();
              break;
            }
            case INV:
            {
              int j;
              m_nodeStats->invReceivedMessages += 1;
              std::vector<std::string>            requestTxs;
              for (j=0; j<d["inv"].Size(); j++)
              {
                std::string   parsedInv = d["inv"][j].GetString();
                if(std::find(knownTxHashes.begin(), knownTxHashes.end(), parsedInv) != knownTxHashes.end()) {
                  std::cout << "Node: " <<  GetNode()->GetId() << ", got dup: " << parsedInv << " From: " <<  InetSocketAddress::ConvertFrom(from).GetIpv4() << "\n";
                  continue;
                } else {
                  std::cout << "Node: " <<  GetNode()->GetId() << ", got first time: " << parsedInv << " From: " <<  InetSocketAddress::ConvertFrom(from).GetIpv4() << "\n";
                }
                knownTxHashes.push_back(parsedInv);

                requestTxs.push_back(parsedInv);
              }

              // Do not need to send getData
              if (requestTxs.size() == 0)
                break;

              rapidjson::Value   value;
              rapidjson::Value   array(rapidjson::kArrayType);
              d.RemoveMember("inv");

              for (auto tx_it = requestTxs.begin(); tx_it < requestTxs.end(); tx_it++)
              {
                value.SetString(tx_it->c_str(), tx_it->size(), d.GetAllocator());
                array.PushBack(value, d.GetAllocator());
              }

              d.AddMember("transactions", array, d.GetAllocator());
              SendMessage(INV, GET_DATA, d, from);
              break;
            }
            case GET_DATA:
            {
              NS_LOG_INFO ("GET_DATA");
              m_nodeStats->getDataReceivedMessages += 1;
              SendMessage(GET_DATA, TX, d, from);
              break;
            }
            case TX:
            {
              rapidjson::StringBuffer buffer;
              rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
              d.Accept(writer);

              for (int j=0; j<d["transactions"].Size(); j++)
              {
                std::string   parsedInv = d["transactions"][j].GetString();
                m_nodeStats->txReceivedTimes[parsedInv] = Simulator::Now().GetSeconds();

                // processing delay
                auto delay = 0.1;
                Simulator::Schedule(Seconds(delay), &BitcoinNode::AdvertiseNewTransactionInv, this, from, parsedInv);
                // AdvertiseNewTransactionInv(from, parsedInv);
              }
            }
            default:
              NS_LOG_INFO ("Default");
              break;
          }

          totalReceivedData.erase(0, pos + delimiter.length());
        }

        /**
        * Buffer the remaining data
        */

        m_bufferedData[from] = totalReceivedData;
        delete[] packetInfo;
      }
      else if (Inet6SocketAddress::IsMatchingType (from))
      {
        NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                     << "s bitcoin node " << GetNode ()->GetId () << " received "
                     <<  packet->GetSize () << " bytes from "
                     << Inet6SocketAddress::ConvertFrom(from).GetIpv6 ()
                     << " port " << Inet6SocketAddress::ConvertFrom (from).GetPort ());
      }
      m_rxTrace (packet, from);
  }
}



void
BitcoinNode::AdvertiseNewTransactionInv (Address from, const std::string transactionHash)
{
  NS_LOG_FUNCTION (this);

  rapidjson::Document inv;
  inv.SetObject();


  rapidjson::Value value;
  rapidjson::Value array(rapidjson::kArrayType);
  rapidjson::Value transactionInfo(rapidjson::kObjectType);

  value.SetString("tx");
  inv.AddMember("type", value, inv.GetAllocator());

  value = INV;
  inv.AddMember("message", value, inv.GetAllocator());

  value.SetString(transactionHash.c_str(), transactionHash.size(), inv.GetAllocator());
  array.PushBack(value, inv.GetAllocator());

  inv.AddMember("inv", array, inv.GetAllocator());

  const uint8_t delimiter[] = "#";
  rapidjson::StringBuffer invInfo;
  rapidjson::Writer<rapidjson::StringBuffer> invWriter(invInfo);
  inv.Accept(invWriter);


  uint numberHash = std::hash<std::string>()(transactionHash);

  for (std::vector<Ipv4Address>::const_iterator i = m_peersAddresses.begin(); i != m_peersAddresses.end(); ++i)
  {
    if (m_protocolType == FILTERS_ON_LINKS && filters[from] && (numberHash % 8) != filters[from]) {
      continue;
    }

    if (blocksOnlyMode[*i]) {
      continue;
    }

    if ( *i != InetSocketAddress::ConvertFrom(from).GetIpv4() )
    {
      // std::cout << "node " << GetNode()->GetId() << " retransmit a packet " << transactionHash << " to " << *i << "\n";
      m_peersSockets[*i]->Send (reinterpret_cast<const uint8_t*>(invInfo.GetString()), invInfo.GetSize(), 0);
      m_peersSockets[*i]->Send (delimiter, 1, 0);
      m_nodeStats->invSentMessages += 1;
      m_nodeStats->invSentBytes += m_bitcoinMessageHeader + m_countBytes + inv["inv"].Size()*m_inventorySizeBytes;
    }
  }
}

void
BitcoinNode::SendMessage(enum Messages receivedMessage,  enum Messages responseMessage, rapidjson::Document &d, Address &outgoingAddress)
{
  NS_LOG_FUNCTION (this);

  const uint8_t delimiter[] = "#";

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  d["message"].SetInt(responseMessage);
  d.Accept(writer);
  NS_LOG_INFO ("Node " << GetNode ()->GetId () << " got a "
               << getMessageName(receivedMessage) << " message"
               << " and sent a " << getMessageName(responseMessage)
               << " message: " << buffer.GetString());

  Ipv4Address outgoingIpv4Address = InetSocketAddress::ConvertFrom(outgoingAddress).GetIpv4 ();
  std::map<Ipv4Address, Ptr<Socket>>::iterator it = m_peersSockets.find(outgoingIpv4Address);

  if (it == m_peersSockets.end()) //Create the socket if it doesn't exist
  {
    m_peersSockets[outgoingIpv4Address] = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
    m_peersSockets[outgoingIpv4Address]->Connect (InetSocketAddress (outgoingIpv4Address, m_bitcoinPort));
  }

  m_peersSockets[outgoingIpv4Address]->Send (reinterpret_cast<const uint8_t*>(buffer.GetString()), buffer.GetSize(), 0);
  m_peersSockets[outgoingIpv4Address]->Send (delimiter, 1, 0);


  switch (d["message"].GetInt())
  {
    case INV:
    {
      m_nodeStats->invSentBytes += m_bitcoinMessageHeader + m_countBytes + d["inv"].Size()*m_inventorySizeBytes;
      m_nodeStats->invSentMessages += 1;
      break;
    }
    case GET_DATA:
    {
      m_nodeStats->getDataSentBytes += m_bitcoinMessageHeader + m_countBytes + d["transactions"].Size()*m_inventorySizeBytes;
      m_nodeStats->getDataSentMessages += 1;
      break;
    }
  }
}



void
BitcoinNode::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void BitcoinNode::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}


void
BitcoinNode::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&BitcoinNode::HandleRead, this));
}


} // Namespace ns3
