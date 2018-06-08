/**
 * This file contains declares the simple BitcoinNode class.
 */

#ifndef BITCOIN_NODE_H
#define BITCOIN_NODE_H

#include <algorithm>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "bitcoin.h"
#include "ns3/boolean.h"
#include "../../rapidjson/document.h"
#include "../../rapidjson/writer.h"
#include "../../rapidjson/stringbuffer.h"

namespace ns3 {

class Address;
class Socket;
class Packet;


class BitcoinNode : public Application
{
public:

  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);
  BitcoinNode (void);

  virtual ~BitcoinNode (void);

  /**
   * \return pointer to listening socket
   */
  Ptr<Socket> GetListeningSocket (void) const;


  /**
   * \return a vector containing the addresses of peers
   */
  std::vector<Ipv4Address> GetPeersAddresses (void) const;


  /**
   * \brief Set the addresses of peers
   * \param peers the reference of a vector containing the Ipv4 addresses of peers
   */
  void SetPeersAddresses (const std::vector<Ipv4Address> &peers);

  /**
   * \brief set the download speeds of peers
   * \param peersDownloadSpeeds the reference of a map containing the Ipv4 addresses of peers and their corresponding download speed
   */
  void SetPeersDownloadSpeeds (const std::map<Ipv4Address, double> &peersDownloadSpeeds);

  /**
   * \brief Set the upload speeds of peers
   * \param peersUploadSpeeds the reference of a map containing the Ipv4 addresses of peers and their corresponding upload speed
  */
  void SetPeersUploadSpeeds (const std::map<Ipv4Address, double> &peersUploadSpeeds);

  /**
   * \brief Set the internet speeds of the node
   * \param internetSpeeds a struct containing the download and upload speed of the node
   */
  void SetNodeInternetSpeeds (const nodeInternetSpeeds &internetSpeeds);

  /**
   * \brief Set the node statistics
   * \param nodeStats a reference to a nodeStatistics struct
   */
  void SetNodeStats(nodeStatistics *nodeStats);

  void SetProperties(uint64_t txToCreate, enum ProtocolType protocol, enum ModeType mode, int netGroups);

protected:
  virtual void DoDispose (void);           // inherited from Application base class.

  virtual void StartApplication (void);    // Called at time specified by Start
  virtual void StopApplication (void);     // Called at time specified by Stop

  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleRead (Ptr<Socket> socket);

  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAccept (Ptr<Socket> socket, const Address& from);

  /**
   * \brief Handle an connection close
   * \param socket the connected socket
   */
  void HandlePeerClose (Ptr<Socket> socket);

  /**
   * \brief Handle an connection error
   * \param socket the connected socket
   */
  void HandlePeerError (Ptr<Socket> socket);



  void AnnounceFilters(void);
  void AnnounceMode(void);

  void ScheduleNextTransactionEvent(void);
  void EmitTransaction(void);

  void ScheduleNextBlockEvent(void);
  void EmitBlock(void);


  void AdvertiseNewTransactionInv (Address from, const std::string transactionHash, int hopNumber);

  void SendInvToNode(Ipv4Address receiver, const std::string transactionHash, int hopNumber);

  /**
   * \brief Sends a message to a peer
   * \param receivedMessage the type of the received message
   * \param responseMessage the type of the response message
   * \param d the rapidjson document containing the info of the outgoing message
   * \param outgoingSocket the socket of the peer
   */
  void SendMessage(enum Messages receivedMessage,  enum Messages responseMessage, rapidjson::Document &d, Ptr<Socket> outgoingSocket);

  /**
   * \brief Sends a message to a peer
   * \param receivedMessage the type of the received message
   * \param responseMessage the type of the response message
   * \param d the rapidjson document containing the info of the outgoing message
   * \param outgoingAddress the Address of the peer
   */
  void SendMessage(enum Messages receivedMessage,  enum Messages responseMessage, rapidjson::Document &d, Address &outgoingAddress);

  /**
   * \brief Sends a message to a peer
   * \param receivedMessage the type of the received message
   * \param responseMessage the type of the response message
   * \param packet a string containing the info of the outgoing message
   * \param outgoingAddress the Address of the peer
   */
  void SendMessage(enum Messages receivedMessage,  enum Messages responseMessage, std::string packet, Address &outgoingAddress);

  // In the case of TCP, each socket accept returns a new socket, so the
  // listening socket is stored separately from the accepted sockets
  Ptr<Socket>     m_socket;                           //!< Listening socket
  Address         m_local;                            //!< Local address to bind to
  TypeId          m_tid;                              //!< Protocol TypeId
  int             m_numberOfPeers;                    //!< Number of node's peers
  double		  m_meanBlockReceiveTime;             //!< The mean time interval between two consecutive blocks (should be around 10min for bitcoin)
  double		  m_previousBlockReceiveTime;         //!< The time that the node received the previous block
  double		  m_meanBlockPropagationTime;         //!< The mean time that the node has to wait in order to receive a newly mined block
  double		  m_meanBlockSize;                    //!< The mean block size
  Time            m_invTimeoutMinutes;                //!< The block timeout in minutes
  double          m_downloadSpeed;                    //!< The download speed of the node in Bytes/s
  double          m_uploadSpeed;                      //!< The upload speed of the node in Bytes/s
  double          m_averageTransactionSize;           //!< The average transaction size. Needed for compressed blocks
  uint m_fixedTxTimeGeneration;

  std::map<Address, uint32_t> filters;
  std::map<Address, ModeType> peersMode;

  uint lastTxId;
  std::vector<std::string> knownTxHashes;

  uint32_t sentOriginalInvs;
  uint32_t retransmittedInvs;
  uint32_t gotGetData;


  std::map<std::string, std::vector<Address>> peersKnowTx;


  std::vector<Ipv4Address>                            m_peersAddresses;                 //!< The addresses of peers
  std::map<Ipv4Address, double>                       m_peersDownloadSpeeds;            //!< The peersDownloadSpeeds of channels
  std::map<Ipv4Address, double>                       m_peersUploadSpeeds;              //!< The peersUploadSpeeds of channels
  std::map<Ipv4Address, Ptr<Socket>>                  m_peersSockets;                   //!< The sockets of peers
  std::map<std::string, std::vector<Address>>         m_queueInv;                       //!< map holding the addresses of nodes which sent an INV for a particular block
  std::map<std::string, std::vector<Address>>         m_queueChunkPeers;                //!< map holding the addresses of nodes from which we are waiting for a CHUNK, key = block_hash
  std::map<std::string, std::vector<int>>             m_queueChunks;                    //!< map holding the chunks of the blocks which we have not requested yet, key = block_hash
  std::map<std::string, std::vector<int>>             m_receivedChunks;                 //!< map holding the chunks of the blocks which we are currently downloading, key = block_hash
  std::map<std::string, EventId>                      m_invTimeouts;                    //!< map holding the event timeouts of inv messages
  std::map<std::string, EventId>                      m_chunkTimeouts;                  //!< map holding the event timeouts of chunk messages
  std::map<Address, std::string>                      m_bufferedData;                   //!< map holding the buffered data from previous handleRead events
  nodeStatistics                                     *m_nodeStats;                      //!< struct holding the node stats
  std::vector<double>                                 m_sendBlockTimes;                 //!< contains the times of the next sendBlock events
  std::vector<double>                                 m_sendCompressedBlockTimes;       //!< contains the times of the next sendBlock events
  std::vector<double>                                 m_receiveBlockTimes;              //!< contains the times of the next sendBlock events
  std::vector<double>                                 m_receiveCompressedBlockTimes;    //!< contains the times of the next sendBlock events
  enum ProtocolType                                   m_protocol;                   //!< protocol type
  enum ModeType                                       m_mode;

  int m_netGroups;

  uint64_t heardTotal;
  std::vector<int> firstTimeHops;
  bool txCreator;


  Address spy;
  uint64_t       m_txToCreate;

  const int       m_bitcoinPort;               //!< 8333
  const int       m_secondsPerMin;             //!< 60
  const int       m_countBytes;                //!< The size of count variable in messages, 4 Bytes
  const int       m_bitcoinMessageHeader;      //!< The size of the bitcoin Message Header, 90 Bytes, including both the bitcoinMessageHeaders and the other protocol headers (TCP, IP, Ethernet)
  const int       m_inventorySizeBytes;        //!< The size of inventories in INV messages, 36 Bytes
  const int       m_getHeadersSizeBytes;       //!< The size of the GET_HEADERS message, 72 Bytes
  const int       m_headersSizeBytes;          //!< 81 Bytes

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;

};

} // namespace ns3

#endif /* BITCOIN_NODE_H */
