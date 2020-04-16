{-# LANGUAGE RecordWildCards  #-}
{-# LANGUAGE TypeApplications #-}

{-- Models and helper methods for working with IPV4 ICMP messages.
 -  https://en.wikipedia.org/wiki/Ping_(networking_utility)
 --}
module Net.ICMP.V4 (
  module Net.ICMP.V4.Internal

, PingPong

, closePingPong
, icmpRecvFrom
, icmpSendTo
, lookupHost
, newIcmpSocket
, newPingPong
, ping
, pingPongId
, pingPongSeq
, pong
) where


import           Control.Concurrent.MVar
import           Control.Exception
import           Control.Monad
import           Data.Binary
import           Data.Bits
import           Data.ByteString.Lazy      (ByteString)
import qualified Data.ByteString.Lazy      as LB
import           Data.Maybe
import           Net.ICMP.V4.Internal
import           Network.Socket
import           Network.Socket.ByteString
import           System.Random             (randomIO)


data PingPong = PingPong
    { _ppSocket :: Socket
    , _ppId     :: Word16
    , _ppSeq    :: MVar Word16
    }

newPingPong :: IO PingPong
newPingPong = PingPong <$> newIcmpSocket <*> randomIO <*> newMVar 0

pingPongId :: PingPong -> Word16
pingPongId = _ppId

pingPongSeq :: PingPong -> IO Word16
pingPongSeq PingPong{..} = readMVar _ppSeq

closePingPong :: PingPong -> IO ()
closePingPong PingPong{..} = close _ppSocket


ping :: PingPong
     -> SockAddr
     -> ByteString -- ^ payload
     -> IO Word16 -- ^ sequence number
ping PingPong{..} addr payload = do
  s <- takeMVar _ppSeq
  putMVar _ppSeq (s+1)

  let hdrDat = shiftL (fromIntegral _ppId) 16 .|. fromIntegral s
      hdr = ICMPHeader EchoRequest 0 hdrDat
      msg = ICMPMessage hdr payload

  void $ icmpSendTo _ppSocket msg addr
  pure s


pong :: PingPong
     -> Int -- ^ max payload bytes to receive
     -> IO (SockAddr, Word16, ByteString) -- ^ addr, sequence, payload
pong pp@PingPong{..} mbytes = do
  (msg@ICMPMessage{..}, sa) <- icmpRecvFrom _ppSocket mbytes

  let ICMPHeader{..} = icmpHeader
      mpid = fromIntegral $ shiftR icmpHeaderData 16
      mseq = fromIntegral icmpHeaderData

  if (msg == icmpAddMessageChecksum msg) && (mpid == _ppId)
  then pure (sa, mseq, icmpPayload)
  else pong pp mbytes


lookupHost :: String
           -> IO (Maybe SockAddr)
lookupHost n = do
  addr <- try @SomeException $ do
    ainfos <- getAddrInfo Nothing (Just n) Nothing
    pure $ addrAddress <$> listToMaybe ainfos
  pure $ either (const Nothing) id addr


newIcmpSocket :: IO Socket
newIcmpSocket = socket AF_INET Raw 1


icmpSendTo :: Socket
           -> ICMPMessage
           -> SockAddr
           -> IO Int
icmpSendTo s m a = do
  let dat = LB.toStrict $ encode $ icmpAddMessageChecksum m
  sendTo s dat a


icmpRecvFrom :: Socket
             -> Int -- ^ max payload bytes
             -> IO (ICMPMessage, SockAddr)
icmpRecvFrom s m = do
  -- received data contains an IPv4 header
  (dat, sa) <- recvFrom s (m + 28) -- 20b IPv4 header + 8b ICMP header
  let icmpDat = (LB.drop 20 . LB.fromStrict) dat
      m1 = decode icmpDat
  pure (m1, sa)
