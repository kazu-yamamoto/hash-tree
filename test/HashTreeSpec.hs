{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}

module HashTreeSpec where

import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base64
import Data.ByteString.Char8 ()
import Data.HashTree
import Data.HashTree.Internal
import Data.List (nub)
import Data.Maybe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck


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
        prop "create a perfectly branched tree" $ \(Input bss) ->
            let Just ht = currentHead $ fromList set bss
                ht' = toHashTree set $ nub bss
            in ht == ht'
    describe "verifyInclusionProof" $ do
        prop "can verify for a good target" $ \(Input bss0) x0 y0 ->
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
        it "can verify the certificate transparency" $
            verifyConsistencyProof set d1 d2 cProof `shouldBe` True
        prop "can verify" $ \(Input bss) m0 n0 ->
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

toDigest :: ByteString -> Digest SHA256
toDigest x = d
  where
    Right r = decode x
    Just d = digestFromByteString r

{-
% wget 'https://ct.googleapis.com/icarus/ct/v1/get-sth-consistency?first=129596132&second=129721434'
{"consistency":["5mrKRX9GRLriSIAtkX0kdvlnjt/f+P0vTrhmzOdhnzs=","VEqL3Z55VZTVRp45WX7gTdcwxOorltn+uCQpHjv9rjE=","2Euj4VXixjEAGj9p23OMo+ciB1tQ2KXH97TkWgcZLpI=","rG0l6AHdk3TRkgAnwTK1Ys5kU7uuKRkMQSkrES0ocj0=","JSxii5BAGCuwifRNIgIsarVA/aSC/QJNv4kfT9zii3Y=","WPaErDHN/lYCuv8TsvosmAsIDbEOfPNZ/LxqLvuQcdY=","HjN1fCoS6OYw8VH+DAcQPQkCjksWljkvr3AJiZTsi6Y=","liuu+DeQohOzAyQadR3imE0SLo8pSsv9K0Y9f1dGrwA=","oUQV+oip0wozcwv4mmMv4MrP545ugwXDIMU6HkZrfl0=","V9BPc7aq1Sq1XwFV3gMx7/9Wv+8l/81S5Gb+bDriRZE=","h3PJZDxVUsGMPBMEaJsQnqAVjlpuxUPGAUfYCY6TkWY=","Rj09QnLzZ2MmyKjJYkcSO8Ko6lGhgwrnOydn+RdHdeI=","Dc7oYAljc9VEYI8JuvYVyJtTHP8uW7igIKVqnWXgvFs=","tJfBVa+YE0GK8T1L74hkkGmT3QO+mznMf+XrKnS3YOE=","V9uRJUhCpCMwss1i4c85X5ceJnNePXdjAVrxtU6EezY=","nf6Yq8xIs56hgor/mk30dvpaUO1/1w+MUlz8thiEb3o=","SEVW3kh8HQ9Za+LjCoGaAkbbUfYmiwNs3SDasWKS6xo=","96r7XxdWTPAZSygfov9mTTd4Gs6chZfdkznd8HAmzKc=","t6OBvH84uFTwEubekO8rdcv+AlqPcpuZX9pwLYopKGg=","nl6nrmkzk5qSYBiUHN609SD8IH3HuTPYR6r1YWKtWag=","NbPA38XBZUXC5ca/cNcU/mNhq31qg2okTS3kJdptnxg=","Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M=","LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU=","Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="]}
-}
cProof :: ConsistencyProof SHA256
cProof = ConsistencyProof 129596132 129721434 cs
  where
    bs = ["5mrKRX9GRLriSIAtkX0kdvlnjt/f+P0vTrhmzOdhnzs="
         ,"VEqL3Z55VZTVRp45WX7gTdcwxOorltn+uCQpHjv9rjE="
         ,"2Euj4VXixjEAGj9p23OMo+ciB1tQ2KXH97TkWgcZLpI="
         ,"rG0l6AHdk3TRkgAnwTK1Ys5kU7uuKRkMQSkrES0ocj0="
         ,"JSxii5BAGCuwifRNIgIsarVA/aSC/QJNv4kfT9zii3Y="
         ,"WPaErDHN/lYCuv8TsvosmAsIDbEOfPNZ/LxqLvuQcdY="
         ,"HjN1fCoS6OYw8VH+DAcQPQkCjksWljkvr3AJiZTsi6Y="
         ,"liuu+DeQohOzAyQadR3imE0SLo8pSsv9K0Y9f1dGrwA="
         ,"oUQV+oip0wozcwv4mmMv4MrP545ugwXDIMU6HkZrfl0="
         ,"V9BPc7aq1Sq1XwFV3gMx7/9Wv+8l/81S5Gb+bDriRZE="
         ,"h3PJZDxVUsGMPBMEaJsQnqAVjlpuxUPGAUfYCY6TkWY="
         ,"Rj09QnLzZ2MmyKjJYkcSO8Ko6lGhgwrnOydn+RdHdeI="
         ,"Dc7oYAljc9VEYI8JuvYVyJtTHP8uW7igIKVqnWXgvFs="
         ,"tJfBVa+YE0GK8T1L74hkkGmT3QO+mznMf+XrKnS3YOE="
         ,"V9uRJUhCpCMwss1i4c85X5ceJnNePXdjAVrxtU6EezY="
         ,"nf6Yq8xIs56hgor/mk30dvpaUO1/1w+MUlz8thiEb3o="
         ,"SEVW3kh8HQ9Za+LjCoGaAkbbUfYmiwNs3SDasWKS6xo="
         ,"96r7XxdWTPAZSygfov9mTTd4Gs6chZfdkznd8HAmzKc="
         ,"t6OBvH84uFTwEubekO8rdcv+AlqPcpuZX9pwLYopKGg="
         ,"nl6nrmkzk5qSYBiUHN609SD8IH3HuTPYR6r1YWKtWag="
         ,"NbPA38XBZUXC5ca/cNcU/mNhq31qg2okTS3kJdptnxg="
         ,"Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M="
         ,"LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU="
         ,"Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="
         ]
    cs = map toDigest bs

{-
% wget https://ct.googleapis.com/icarus/ct/v1/get-sth
{"tree_size":129596132,"timestamp":1508198131197,"sha256_root_hash":"qyJv/TObheataX8uFjAJsR+dJtJgNlfjzTe5CX8Ej2s=","tree_head_signature":"BAMASDBGAiEAhtcpfpVSKRuZOxEMpPRRiu5nPdd8UL3JnQBk23Zrk/ACIQD+n4YSigh3o1KaJvBTvJkcmq2CW5QtrIBdI2oDiItN1A=="}
-}
d1 :: Digest SHA256
d1 = toDigest "qyJv/TObheataX8uFjAJsR+dJtJgNlfjzTe5CX8Ej2s="

{-
% wget https://ct.googleapis.com/icarus/ct/v1/get-sth
{"tree_size":129721434,"timestamp":1508216080417,"sha256_root_hash":"jhnkzC7e95jLNBJSiQRnuH2sXYfpY6sASO3ezfUBU0w=","tree_head_signature":"BAMARzBFAiBkiNQdBXnYQLwbcSxPYjvKYatziAbADq124OifIeZ2oQIhAOzYM60DNII1ILtWDMvCPcGqTapkb/Ru4KIJJwdTi+dg"}
-}
d2 :: Digest SHA256
d2 = toDigest "jhnkzC7e95jLNBJSiQRnuH2sXYfpY6sASO3ezfUBU0w="
