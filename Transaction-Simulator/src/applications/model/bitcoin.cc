/**
 * This file contains the definitions of the functions declared in bitcoin.h
 */


#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/log.h"
#include "bitcoin.h"

namespace ns3 {


/**
 *
 * Class Block functions
 *
 */

Transaction::Transaction(double timeCreated, double timeReceived, Ipv4Address receivedFromIpv4)
{
  m_timeCreated = timeCreated;
  m_timeReceived = timeReceived;
  m_receivedFromIpv4 = receivedFromIpv4;

}

Transaction::Transaction()
{
  Transaction(0, 0, Ipv4Address("0.0.0.0"));

}

Transaction::~Transaction (void)
{
}

double
Transaction::GetTimeCreated (void) const
{
  return m_timeCreated;
}

double
Transaction::GetTimeReceived (void) const
{
  return m_timeReceived;
}


Ipv4Address
Transaction::GetReceivedFromIpv4 (void) const
{
  return m_receivedFromIpv4;
}

void
Transaction::SetReceivedFromIpv4 (Ipv4Address receivedFromIpv4)
{
  m_receivedFromIpv4 = receivedFromIpv4;
}

//
// Transaction&
// Transaction::operator= (const Transaction &txSource)
// {
//   m_timeCreated = txSource.m_timeCreated;
//   m_timeReceived = txSource.m_timeReceived;
//   m_receivedFromIpv4 = txSource.m_receivedFromIpv4;
//
//   return *this;
// }

bool operator== (const Transaction &tx1, const Transaction &tx2)
{
    // TODO Fix
    return false;
}

// TODO Write
//
// std::ostream& operator<< (std::ostream &out, const Block &block)
// {
//
//     out << "(m_blockHeight: " << block.GetBlockHeight() << ", " <<
//         "m_minerId: " << block.GetMinerId() << ", " <<
//         "m_parentBlockMinerId: " << block.GetParentBlockMinerId() << ", " <<
//         "m_blockSizeBytes: " << block.GetBlockSizeBytes() << ", " <<
//         "m_timeCreated: " << block.GetTimeCreated() << ", " <<
//         "m_timeReceived: " << block.GetTimeReceived() << ", " <<
//         "m_receivedFromIpv4: " << block.GetReceivedFromIpv4() <<
//         ")";
//     return out;
// }


const char* getMessageName(enum Messages m)
{
  switch (m)
  {
    case INV: return "INV";
    case GET_DATA: return "GET_DATA";
  }
}


const char* getProtocolType(enum ProtocolType m)
{
  switch (m)
  {
    case STANDARD_PROTOCOL: return "STANDARD_PROTOCOL";
    case NEW_PROTOCOL: return "NEW_PROTOCOL";
  }
}

const char* getCryptocurrency(enum Cryptocurrency m)
{
  switch (m)
  {
    case BITCOIN: return "BITCOIN";
  }
}

const char* getBitcoinRegion(enum BitcoinRegion m)
{
  switch (m)
  {
    case ASIA_PACIFIC: return "ASIA_PACIFIC";
    case AUSTRALIA: return "AUSTRALIA";
    case EUROPE: return "EUROPE";
    case JAPAN: return "JAPAN";
    case NORTH_AMERICA: return "NORTH_AMERICA";
    case SOUTH_AMERICA: return "SOUTH_AMERICA";
    case OTHER: return "OTHER";
  }
}


enum BitcoinRegion getBitcoinEnum(uint32_t n)
{
  switch (n)
  {
    case 0: return NORTH_AMERICA;
    case 1: return EUROPE;
    case 2: return SOUTH_AMERICA;
    case 3: return ASIA_PACIFIC;
    case 4: return JAPAN;
    case 5: return AUSTRALIA;
    case 6: return OTHER;
  }
}
}// Namespace ns3
