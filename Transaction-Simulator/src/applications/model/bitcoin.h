/**
 * This file contains all the necessary enumerations and structs used throughout the simulation.
 * It also defines 3 very important classed; the Block, Chunk and Blockchain.
 */


#ifndef BITCOIN_H
#define BITCOIN_H

#include <vector>
#include <map>
#include "ns3/address.h"
#include <algorithm>

namespace ns3 {

/**
 * The bitcoin message types that have been implemented.
 */
enum Messages
{
  INV,              //0
  GET_DATA,         //1
  TX,
  FILTER,
  MODE,
  BLOCK
};

enum ProtocolType
{
  STANDARD_PROTOCOL,           //DEFAULT
  FILTERS_ON_LINKS
};


/**
 * The different cryptocurrency networks that the simulation supports.
 */
enum Cryptocurrency
{
  BITCOIN,                     //DEFAULT
  LITECOIN,
  DOGECOIN
};


/**
 * The geographical regions used in the simulation. OTHER was only used for debugging reasons.
 */
enum BitcoinRegion
{
  NORTH_AMERICA,    //0
  EUROPE,           //1
  SOUTH_AMERICA,    //2
  ASIA_PACIFIC,     //3
  JAPAN,            //4
  AUSTRALIA,        //5
  OTHER             //6
};


/**
 * The struct used for collecting node statistics.
 */
typedef struct {
  int      nodeId;
  long     invReceivedBytes;
  long     invSentBytes;
  int64_t     invReceivedMessages;
  int64_t     invSentMessages;
  long     getDataReceivedBytes;
  long     getDataSentBytes;
  int64_t     getDataReceivedMessages;
  int64_t     getDataSentMessages;
  int64_t txCreated;
  int      connections;

  int      blocksRelayed;

  bool blocksOnly;

  std::map<std::string, double> txReceivedTimes;
} nodeStatistics;


typedef struct {
  double downloadSpeed;
  double uploadSpeed;
} nodeInternetSpeeds;


/**
 * Fuctions used to convert enumeration values to the corresponding strings.
 */
const char* getMessageName(enum Messages m);
const char* getProtocolType(enum ProtocolType m);
const char* getBitcoinRegion(enum BitcoinRegion m);
const char* getCryptocurrency(enum Cryptocurrency m);
enum BitcoinRegion getBitcoinEnum(uint32_t n);

class Transaction
{
public:
  Transaction (double timeCreated = 0, double timeReceived = 0, Ipv4Address receivedFromIpv4 = Ipv4Address("0.0.0.0"));
  Transaction ();
  virtual ~Transaction (void);
  // Transaction (const Transaction &txSource);  // Copy constructor


  double GetTimeCreated (void) const;
  double GetTimeReceived (void) const;

  Ipv4Address GetReceivedFromIpv4 (void) const;
  void SetReceivedFromIpv4 (Ipv4Address receivedFromIpv4);

  friend bool operator== (const Transaction &tx1, const Transaction &tx2);
  friend std::ostream& operator<< (std::ostream &out, const Transaction &tx);

protected:
  double        m_timeCreated;                // The time the block was created
  double        m_timeReceived;               // The time the block was received from the node
  Ipv4Address   m_receivedFromIpv4;           // The Ipv4 of the node which sent the block to the receiving node
};

}// Namespace ns3

#endif /* BITCOIN_H */
