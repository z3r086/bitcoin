/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <fstream>
#include <time.h>
#include <sys/time.h>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/mpi-interface.h"
#define MPI_TEST

#ifdef NS3_MPI
#include <mpi.h>
#endif

using namespace ns3;

double get_wall_time();
int GetNodeIdByIpv4 (Ipv4InterfaceContainer container, Ipv4Address addr);
void PrintStatsForEachNode (nodeStatistics *stats, int totalNodes, int publicIPNodes);
void PrintTotalStats (nodeStatistics *stats, int totalNodes, double start, double finish, double averageBlockGenIntervalMinutes, bool relayNetwork);
void PrintBitcoinRegionStats (uint32_t *bitcoinNodesRegions, uint32_t totalNodes);

NS_LOG_COMPONENT_DEFINE ("MyMpiTest");

int
main (int argc, char *argv[])
{
  std::cout << "Start \n";

  bool nullmsg = false;
  bool testScalability = false;
  int invTimeoutMins = -1;
  enum Cryptocurrency  cryptocurrency = BITCOIN;
  double tStart = get_wall_time(), tStartSimulation, tFinish;
  const int secsPerMin = 60;
  const uint16_t bitcoinPort = 8333;
  int start = 0;
//
  int totalNoNodes = 16;
  int minConnectionsPerNode = -1;
  int maxConnectionsPerNode = -1;

  uint64_t txToCreate = 1024;
  int publicIPNodes;

  double stop;


//
  Ipv4InterfaceContainer                               ipv4InterfaceContainer;
  std::map<uint32_t, std::vector<Ipv4Address>>         nodesConnections;
  std::map<uint32_t, std::map<Ipv4Address, double>>    peersDownloadSpeeds;
  std::map<uint32_t, std::map<Ipv4Address, double>>    peersUploadSpeeds;
  std::map<uint32_t, nodeInternetSpeeds>               nodesInternetSpeeds;
  int                                                  nodesInSystemId0 = 0;

  Time::SetResolution (Time::NS);

  CommandLine cmd;
  cmd.AddValue ("nullmsg", "Enable the use of null-message synchronization", nullmsg);
  cmd.AddValue ("nodes", "The total number of nodes in the network", totalNoNodes);
  cmd.AddValue ("minConnections", "The minConnectionsPerNode of the grid", minConnectionsPerNode);
  cmd.AddValue ("maxConnections", "The maxConnectionsPerNode of the grid", maxConnectionsPerNode);
  cmd.AddValue ("invTimeoutMins", "The inv block timeout", invTimeoutMins);
  cmd.AddValue ("test", "Test the scalability of the simulation", testScalability);

  cmd.AddValue ("txToCreatePerNode", "The number of transactions each of the chosen nodes should generate", txToCreate);

  cmd.AddValue ("publicIPNodes", "How many nodes has public IP", publicIPNodes);

  cmd.Parse(argc, argv);

  // TODO Configure
  uint averageBlockGenInterval = 10 * 60;
  uint targetNumberOfBlocks = 100;

  stop = targetNumberOfBlocks * averageBlockGenInterval; //seconds
  nodeStatistics *stats = new nodeStatistics[totalNoNodes];

  uint32_t systemId = 0;
  uint32_t systemCount = 1;


  LogComponentEnable("BitcoinNode", LOG_LEVEL_INFO);

  BitcoinTopologyHelper bitcoinTopologyHelper (systemCount, totalNoNodes, publicIPNodes, minConnectionsPerNode,
                                               maxConnectionsPerNode, systemId);




  // Install stack on Grid
  InternetStackHelper stack;
  bitcoinTopologyHelper.InstallStack (stack);


  // Assign Addresses to Grid
  bitcoinTopologyHelper.AssignIpv4Addresses (Ipv4AddressHelperCustom ("1.0.0.0", "255.255.255.0", false));
  ipv4InterfaceContainer = bitcoinTopologyHelper.GetIpv4InterfaceContainer();
  nodesConnections = bitcoinTopologyHelper.GetNodesConnectionsIps();
  peersDownloadSpeeds = bitcoinTopologyHelper.GetPeersDownloadSpeeds();
  peersUploadSpeeds = bitcoinTopologyHelper.GetPeersUploadSpeeds();
  nodesInternetSpeeds = bitcoinTopologyHelper.GetNodesInternetSpeeds();


  std::cout << "Total nodes: " << totalNoNodes << "\n";

  int count = 0;


  //Install simple nodes
  BitcoinNodeHelper bitcoinNodeHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), bitcoinPort),
                                        nodesConnections[0], peersDownloadSpeeds[0],  peersUploadSpeeds[0], nodesInternetSpeeds[0], stats);
  ApplicationContainer bitcoinNodes;

  for(auto &node : nodesConnections)
  {
    Ptr<Node> targetNode = bitcoinTopologyHelper.GetNode (node.first);

  	if (systemId == targetNode->GetSystemId())
  	{
      bitcoinNodeHelper.SetPeersAddresses (node.second);
      bitcoinNodeHelper.SetPeersDownloadSpeeds (peersDownloadSpeeds[node.first]);
      bitcoinNodeHelper.SetPeersUploadSpeeds (peersUploadSpeeds[node.first]);
      bitcoinNodeHelper.SetNodeInternetSpeeds (nodesInternetSpeeds[node.first]);

      // Setting tx to create limit
      if (nodesInSystemId0 < publicIPNodes) {
        bitcoinNodeHelper.SetProperties(0);
      } else {
        bitcoinNodeHelper.SetProperties(txToCreate);
      }

  	  bitcoinNodeHelper.SetNodeStats (&stats[node.first]);

      bitcoinNodes.Add(bitcoinNodeHelper.Install (targetNode));
      // std::cout << "SystemId " << systemId << ": Node " << node.first << " with systemId = " << targetNode->GetSystemId()
  	  //         << " was installed in node " << targetNode->GetId () <<  std::endl;

      if (systemId == 0)
          nodesInSystemId0++;
  	}
  }
  std::cout << "start: " << start << "\n";
  std::cout << "stop: " << stop << "\n";

  bitcoinNodes.Start (Seconds (start));
  bitcoinNodes.Stop (Minutes (stop));



  if (systemId == 0)
    std::cout << "The applications have been setup.\n";

  tStartSimulation = get_wall_time();
  if (systemId == 0)
    std::cout << "Setup time = " << tStartSimulation - tStart << "s\n";
  Simulator::Stop (Minutes (stop + 0.1));
  Simulator::Run ();
  Simulator::Destroy ();

  if (systemId == 0)
  {
    tFinish=get_wall_time();

    PrintStatsForEachNode(stats, totalNoNodes, publicIPNodes);
    // PrintTotalStats(stats, totalNoNodes, tStartSimulation, tFinish, averageBlockGenIntervalMinutes, relayNetwork);


    std::cout << "\nThe simulation ran for " << tFinish - tStart << "s simulating "
              << stop << "mins. Performed " << stop * secsPerMin / (tFinish - tStart)
              << " faster than realtime.\n" << "Setup time = " << tStartSimulation - tStart << "s\n"
              <<"It consisted of " << totalNoNodes << " nodes ( with minConnectionsPerNode = "
              << minConnectionsPerNode << " and maxConnectionsPerNode = " << maxConnectionsPerNode
              << "\n";

  }

  delete[] stats;

  return 0;
//
// #else
//   NS_FATAL_ERROR ("Can't use distributed simulator without MPI compiled in");
// #endif
}

double get_wall_time()
{
    struct timeval time;
    if (gettimeofday(&time,NULL)){
        //  Handle error
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}

int GetNodeIdByIpv4 (Ipv4InterfaceContainer container, Ipv4Address addr)
{
  for (auto it = container.Begin(); it != container.End(); it++)
  {
	int32_t interface = it->first->GetInterfaceForAddress (addr);
	if ( interface != -1)
      return it->first->GetNetDevice (interface)-> GetNode()->GetId();
  }
  return -1; //if not found
}

void PrintStatsForEachNode (nodeStatistics *stats, int totalNodes, int publicIPNodes)
{
  float totalUsefulInvSentRatePublicIPNode = 0;
  float totalUsefulInvSentRatePrivateIPNode = 0;
  float totalUsefulInvReceivedRate = 0;
  float totaluselessInvSentMegabytesPublicIPNode = 0;

  for (int it = 0; it < totalNodes; it++ )
  {
    std::cout << "\nNode " << stats[it].nodeId << " statistics:\n";
    std::cout << "Connections = " << stats[it].connections << "\n";
    std::cout << "Transactions created = " << stats[it].txCreated << "\n";
    std::cout << "Inv sent = " << stats[it].invSentMessages << "\n";
    std::cout << "Inv received = " << stats[it].invReceivedMessages << "\n";
    std::cout << "GetData sent = " << stats[it].getDataSentMessages << "\n";
    std::cout << "GetData received = " << stats[it].getDataReceivedMessages << "\n";

    std::cout << "GetData sent = " << stats[it].getDataSentMessages << "\n";
    std::cout << "GetData received = " << stats[it].getDataReceivedMessages << "\n";



    float usefulInvSentRate = float(stats[it].getDataReceivedMessages) / stats[it].invSentMessages;
    float usefulInvReceivedRate = float(stats[it].getDataSentMessages) / stats[it].invReceivedMessages;
    float invSentMegabytes = float(stats[it].invSentBytes) / 1024 / 1024;

    std::cout << "Inv sent megabytes = " << invSentMegabytes << "\n";
    std::cout << "Useless inv sent megabytes = " << (1.0-usefulInvSentRate) * invSentMegabytes << "\n";

    std::cout << "Useful inv sent rate = " << usefulInvSentRate << "\n";
    std::cout << "Useful inv received rate = " << usefulInvReceivedRate << "\n";

    if (it < publicIPNodes) {
      totalUsefulInvSentRatePublicIPNode += usefulInvSentRate;
      totaluselessInvSentMegabytesPublicIPNode += (1.0-usefulInvSentRate) * invSentMegabytes;
    }

    if (it >= publicIPNodes)
      totalUsefulInvSentRatePrivateIPNode += usefulInvSentRate;


    totalUsefulInvReceivedRate += usefulInvReceivedRate;

  }

  std::cout << "Average useful inv sent rate (public IP nodes) =" << totalUsefulInvSentRatePublicIPNode / publicIPNodes << "\n";
  std::cout << "Average useful inv sent rate (private IP nodes) = " << totalUsefulInvSentRatePrivateIPNode / (totalNodes - publicIPNodes) << "\n";

  std::cout << "Average useful inv received rate (all) = " << totalUsefulInvReceivedRate / totalNodes << "\n";

  std::cout << "Average useless inv megabytes sent (public IP) = " << totaluselessInvSentMegabytesPublicIPNode / publicIPNodes << "\n";

}



void PrintTotalStats (nodeStatistics *stats, int totalNodes, double start, double finish, double averageBlockGenIntervalMinutes, bool relayNetwork)
{
}
