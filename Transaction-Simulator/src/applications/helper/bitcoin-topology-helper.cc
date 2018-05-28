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
 *
 * Author: Josh Pelkey <jpelkey@gatech.edu>
 */

#include "ns3/bitcoin-topology-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/constant-position-mobility-model.h"
#include "ns3/string.h"
#include "ns3/vector.h"
#include "ns3/log.h"
#include "ns3/ipv6-address-generator.h"
#include "ns3/random-variable-stream.h"
#include "ns3/double.h"
#include <algorithm>
#include <fstream>
#include <time.h>
#include <sys/time.h>
#include <array>

static double GetWallTime();
namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("BitcoinTopologyHelper");

BitcoinTopologyHelper::BitcoinTopologyHelper (uint32_t noCpus, uint32_t totalNoNodes, uint32_t publicIPNodes, int minConnectionsPerNode, int maxConnectionsPerNode,
						                                       uint32_t systemId)
  : m_noCpus(noCpus), m_totalNoNodes (totalNoNodes),
    m_minConnectionsPerNode (minConnectionsPerNode), m_maxConnectionsPerNode (maxConnectionsPerNode),
	m_totalNoLinks (0), m_publicIPNodes(publicIPNodes),
	m_systemId (systemId)
{

  std::vector<uint32_t>     nodes;    //nodes contain the ids of the nodes
  double                    tStart = GetWallTime();
  double                    tFinish;
  srand (1000);


  std::array<double,7> nodesDistributionIntervals {NORTH_AMERICA, EUROPE, SOUTH_AMERICA, ASIA_PACIFIC, JAPAN, AUSTRALIA, OTHER};

  if (m_systemId == 0)
    std::cout << "BITCOIN Mode selected\n";
  std::array<double,6> nodesDistributionWeights {38.69, 51.59, 1.13, 5.74, 1.19, 1.66};
  m_nodesDistribution = std::piecewise_constant_distribution<double> (nodesDistributionIntervals.begin(), nodesDistributionIntervals.end(), nodesDistributionWeights.begin());



  std::array<double,7> connectionsDistributionIntervals {1, 5, 10, 15, 20, 30, 125};
  for (int i = 0; i < 7; i++)
	connectionsDistributionIntervals[i] -= i;

  std::array<double,6> connectionsDistributionWeights {10, 40, 30, 13, 6, 1};

  m_connectionsDistribution = std::piecewise_constant_distribution<double> (connectionsDistributionIntervals.begin(), connectionsDistributionIntervals.end(), connectionsDistributionWeights.begin());


  for (int i = 0; i < m_totalNoNodes; i++)
  {
    nodes.push_back(i);
  }


  for(int i = 0; i < m_totalNoNodes; i++)
  {
	  m_minConnections[i] = m_minConnectionsPerNode;
    if (i >= publicIPNodes)
      m_maxConnections[i] = m_minConnectionsPerNode;
    else
      m_maxConnections[i] = m_maxConnectionsPerNode;
  }

  for(int i = 0; i < m_totalNoNodes; i++)
  {
	int count = 0;

    while (m_nodesConnections[i].size() < m_minConnections[i] && count < 10*m_minConnections[i])
    {
      // Choose from publicIP nodes only
      uint32_t index = rand() % publicIPNodes;
      // uint32_t index = rand() % nodes.size();
	    uint32_t candidatePeer = nodes[index];

      if (candidatePeer == i)
      {
   		  // if (m_systemId == 0)
        //     std::cout << "Node " << i << " does not need a connection with itself" << "\n";
      }
      else if (std::find(m_nodesConnections[i].begin(), m_nodesConnections[i].end(), candidatePeer) != m_nodesConnections[i].end())
      {
   		  // if (m_systemId == 0)
        //     std::cout << "Node " << i << " has already a connection to Node " << nodes[index] << "\n";
      }
      else if (m_nodesConnections[candidatePeer].size() >= m_maxConnections[candidatePeer])
      {
 		     // if (m_systemId == 0)
         //    std::cout << "Node " << nodes[index] << " has already " << m_maxConnections[candidatePeer] << " connections" << "\n";
      }
      else
      {
        m_nodesConnections[i].push_back(candidatePeer);
        m_nodesConnections[candidatePeer].push_back(i);

        if (m_nodesConnections[candidatePeer].size() == m_maxConnections[candidatePeer])
        {
/* 		  if (m_systemId == 0)
            std::cout << "Node " << nodes[index] << " is removed from index\n"; */
          nodes.erase(nodes.begin() + index);
        }
      }
      count++;
	   }
  }



  //Print the nodes with fewer than required connections
  if (m_systemId == 0)
  {
    for(int i = 0; i < m_totalNoNodes; i++)
    {
  	  if (m_nodesConnections[i].size() < m_minConnections[i])
  	    std::cout << "Node " << i << " should have at least " << m_minConnections[i] << " connections but it has only " << m_nodesConnections[i].size() << " connections\n";
    }
  }

  //Print the nodes' connections
  if (m_systemId == 0)
  {
    std::cout << "The nodes connections are:" << std::endl;
    for(auto &node : m_nodesConnections)
    {
  	  std::cout << "\nNode " << node.first << ":    " ;
	  for(std::vector<uint32_t>::const_iterator it = node.second.begin(); it != node.second.end(); it++)
	  {
        std::cout  << "\t" << *it;
	  }
    }
    std::cout << "\n" << std::endl;
  }

  //Print the nodes' connections distribution
  if (m_systemId == 0)
  {
	int *stats = new int[connectionsDistributionIntervals.size()];
	double averageNoConnectionsPerNode = 0;



    std::cout << "Average Number of Connections Per Node = " << averageNoConnectionsPerNode / (m_totalNoNodes);

	delete[] stats;
  }

  tFinish = GetWallTime();
  if (m_systemId == 0)
  {
    std::cout << "The nodes connections were created in " << tFinish - tStart << "s.\n";
    std::cout << "The minimum number of connections for each node is " << m_minConnectionsPerNode
              << " and whereas the maximum is " << m_maxConnectionsPerNode << ".\n";
  }


  InternetStackHelper stack;

  std::ostringstream latencyStringStream;
  std::ostringstream bandwidthStream;

  PointToPointHelper pointToPoint;

  tStart = GetWallTime();
  //Create the bitcoin nodes
  for (uint32_t i = 0; i < m_totalNoNodes; i++)
  {
    NodeContainer currentNode;
    currentNode.Create (1, i % m_noCpus);
/* 	if (m_systemId == 0)
      std::cout << "Creating a node with Id = " << i << " and systemId = " << i % m_noCpus << "\n"; */
    m_nodes.push_back (currentNode);
  }



  tFinish = GetWallTime();
  if (m_systemId == 0)
    std::cout << "The nodes were created in " << tFinish - tStart << "s.\n";

  tStart = GetWallTime();



  for(auto &node : m_nodesConnections)
  {

    for(std::vector<uint32_t>::const_iterator it = node.second.begin(); it != node.second.end(); it++)
    {

      if ( *it <= node.first)	//Do not recreate links
        continue;

      // std::cout << "Node: " << node.first <<  ", connects to: " << *it << "\n";

        NetDeviceContainer newDevices;

        m_totalNoLinks++;

		double bandwidth = std::min(std::min(m_nodesInternetSpeeds[m_nodes.at (node.first).Get (0)->GetId()].uploadSpeed,
                                    m_nodesInternetSpeeds[m_nodes.at (node.first).Get (0)->GetId()].downloadSpeed),
                                    std::min(m_nodesInternetSpeeds[m_nodes.at (*it).Get (0)->GetId()].uploadSpeed,
                                    m_nodesInternetSpeeds[m_nodes.at (*it).Get (0)->GetId()].downloadSpeed));
		bandwidthStream.str("");
        bandwidthStream.clear();
		bandwidthStream << bandwidth << "Mbps";

    latencyStringStream.str("");
    latencyStringStream.clear();

    latencyStringStream << 10 << "ms";


		pointToPoint.SetDeviceAttribute ("DataRate", StringValue (bandwidthStream.str()));
		pointToPoint.SetChannelAttribute ("Delay", StringValue (latencyStringStream.str()));

        newDevices.Add (pointToPoint.Install (m_nodes.at (node.first).Get (0), m_nodes.at (*it).Get (0)));
		m_devices.push_back (newDevices);
    }
  }

  tFinish = GetWallTime();

  if (m_systemId == 0)
    std::cout << "The total number of links is " << m_totalNoLinks << " (" << tFinish - tStart << "s).\n";
}

BitcoinTopologyHelper::~BitcoinTopologyHelper ()
{
}

void
BitcoinTopologyHelper::InstallStack (InternetStackHelper stack)
{
  double tStart = GetWallTime();
  double tFinish;

  for (uint32_t i = 0; i < m_nodes.size (); ++i)
    {
      NodeContainer currentNode = m_nodes[i];
      for (uint32_t j = 0; j < currentNode.GetN (); ++j)
        {
          stack.Install (currentNode.Get (j));
        }
    }

  tFinish = GetWallTime();
  if (m_systemId == 0)
    std::cout << "Internet stack installed in " << tFinish - tStart << "s.\n";
}

void
BitcoinTopologyHelper::AssignIpv4Addresses (Ipv4AddressHelperCustom ip)
{
  double tStart = GetWallTime();
  double tFinish;

  // Assign addresses to all devices in the network.
  // These devices are stored in a vector.
  for (uint32_t i = 0; i < m_devices.size (); ++i)
  {
    Ipv4InterfaceContainer newInterfaces;
    NetDeviceContainer currentContainer = m_devices[i];

    newInterfaces.Add (ip.Assign (currentContainer.Get (0)));
    newInterfaces.Add (ip.Assign (currentContainer.Get (1)));

    auto interfaceAddress1 = newInterfaces.GetAddress (0);
    auto interfaceAddress2 = newInterfaces.GetAddress (1);
    uint32_t node1 = (currentContainer.Get (0))->GetNode()->GetId();
    uint32_t node2 = (currentContainer.Get (1))->GetNode()->GetId();

/*     if (m_systemId == 0)
      std::cout << i << "/" << m_devices.size () << "\n"; */
/* 	if (m_systemId == 0)
	  std::cout << "Node " << node1 << "(" << interfaceAddress1 << ") is connected with node  "
                << node2 << "(" << interfaceAddress2 << ")\n"; */




	m_nodesConnectionsIps[node1].push_back(interfaceAddress2);
	m_nodesConnectionsIps[node2].push_back(interfaceAddress1);

    ip.NewNetwork ();

    m_interfaces.push_back (newInterfaces);

	m_peersDownloadSpeeds[node1][interfaceAddress2] = m_nodesInternetSpeeds[node2].downloadSpeed;
	m_peersDownloadSpeeds[node2][interfaceAddress1] = m_nodesInternetSpeeds[node1].downloadSpeed;
	m_peersUploadSpeeds[node1][interfaceAddress2] = m_nodesInternetSpeeds[node2].uploadSpeed;
	m_peersUploadSpeeds[node2][interfaceAddress1] = m_nodesInternetSpeeds[node1].uploadSpeed;
  }


  tFinish = GetWallTime();
  if (m_systemId == 0)
    std::cout << "The Ip addresses have been assigned in " << tFinish - tStart << "s.\n";
}


Ptr<Node>
BitcoinTopologyHelper::GetNode (uint32_t id)
{
  if (id > m_nodes.size () - 1 )
    {
      NS_FATAL_ERROR ("Index out of bounds in BitcoinTopologyHelper::GetNode.");
    }

  return (m_nodes.at (id)).Get (0);
}



Ipv4InterfaceContainer
BitcoinTopologyHelper::GetIpv4InterfaceContainer (void) const
{
  Ipv4InterfaceContainer ipv4InterfaceContainer;

  for (auto container = m_interfaces.begin(); container != m_interfaces.end(); container++)
    ipv4InterfaceContainer.Add(*container);

  return ipv4InterfaceContainer;
}


std::map<uint32_t, std::vector<Ipv4Address>>
BitcoinTopologyHelper::GetNodesConnectionsIps (void) const
{
  return m_nodesConnectionsIps;
}



std::map<uint32_t, std::map<Ipv4Address, double>>
BitcoinTopologyHelper::GetPeersDownloadSpeeds (void) const
{
  return m_peersDownloadSpeeds;
}


std::map<uint32_t, std::map<Ipv4Address, double>>
BitcoinTopologyHelper::GetPeersUploadSpeeds (void) const
{
  return m_peersUploadSpeeds;
}


std::map<uint32_t, nodeInternetSpeeds>
BitcoinTopologyHelper::GetNodesInternetSpeeds (void) const
{
  return m_nodesInternetSpeeds;
}

} // namespace ns3

static double GetWallTime()
{
    struct timeval time;
    if (gettimeofday(&time,NULL)){
        //  Handle error
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}
