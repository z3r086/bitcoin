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

enum ModeType
{
  REGULAR,           //DEFAULT
  BLOCKS_ONLY,
  SPY
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

}// Namespace ns3

#endif /* BITCOIN_H */
