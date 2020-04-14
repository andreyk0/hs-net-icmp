{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Control.Concurrent
import           Control.Monad
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy  as LB
import           Net.ICMP.V4
import           System.Environment    (getArgs)


main :: IO ()
main = do
  args <- getArgs

  let hostname = head args

  pp <- newPingPong

  addrRes <- lookupHost hostname

  addr <- case addrRes
            of Nothing -> error "Failed to lookup addr"
               Just a  -> return a

  exitMv <- newEmptyMVar

  void $ forkIO $ forM_ [(0::Int) ..] $ \i -> do
         let tDat = "testdata_" <> (LB.fromStrict . C.pack . show) i
         s <- ping pp addr tDat
         putStrLn $ "-> " <> show (s, tDat)
         threadDelay 1000000

  let pongLoop = do r@(_,s,_) <- pong pp 128
                    putStrLn $ "<- " <> (show r)
                    when (s > 10) $ putMVar exitMv ()
                    pongLoop

  void $ forkIO pongLoop

  takeMVar exitMv
  closePingPong pp
