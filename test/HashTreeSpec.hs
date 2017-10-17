{-# OPTIONS_GHC -fno-warn-orphans #-}

module HashTreeSpec where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.HashTree.Internal
import Data.Maybe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Data.List (nub)

newtype Input = Input [ByteString] deriving Show -- non empty list

instance Arbitrary ByteString where
    arbitrary = BS.pack <$> listOf arbitrary -- Gen Word8

instance Arbitrary Input where
    arbitrary = Input . getNonEmpty <$> arbitrary -- Gen (NonEmptyList ByteString)

spec :: Spec
spec = do
    let set = defaultSettings
    describe "info" $ do
        prop "The root hash of 1-size tree is equal to the leaf hash" $ \bs ->
            let mht = add (bs :: ByteString) $ empty set
                h1 = snd $ info mht
                h2 = hash1 set bs
            in h1 == h2
    describe "fromList" $ do
        prop "creates a perfectly branched tree" $ \(Input bss) ->
            let Just ht = currentHead $ fromList set bss
                ht' = toHashTree set $ nub bss
            in ht == ht'
    describe "verifyInclusionProof" $ do
        prop "can be verified for a good target" $ \(Input bss0) x0 y0 ->
            let bss = nub bss0
                mht = fromList set bss
                len = length bss
                x0' = adjust x0 len
                y0' = adjust y0 len
                (i,tsiz)
                   | x0' < y0' = (x0',y0')
                   | x0' > y0' = (y0',x0')
                   | otherwise = (x0',y0'+1)
                target = bss !! i
                leafDigest = hash1 set target
                proof = fromJust $ generateInclusionProof leafDigest tsiz mht
                Just rootDigest = digest tsiz mht
            in verifyInclusionProof set leafDigest rootDigest proof
    describe "verifyConsistencyProof" $ do
        prop "can be verified" $ \(Input bss) m0 n0 ->
            let mht = fromList set bss
                siz = size mht
                m0' = adjust m0 siz
                n0' = adjust n0 siz
                (m,n) = if m0' <= n0' then (m0',n0') else (n0',m0')
                proof = fromJust $ generateConsistencyProof m n mht
                Just dm = digest m mht
                Just dn = digest n mht
            in verifyConsistencyProof set dm dn proof

adjust :: Int -> Int -> Int
adjust x b
  | x < 0     = negate x `mod` b
  | otherwise = x `mod` b
