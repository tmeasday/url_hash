require 'helper'
require 'digest'

class TestUrlHash < Test::Unit::TestCase
  context "UrlHash" do
    should "convert between integers and buffers" do
      assert_equal 1001, UrlHash.buffer_to_int(UrlHash.int_to_buffer(1001, 8))
      assert_equal 1001, UrlHash.buffer_to_int(UrlHash.int_to_buffer(1001, 10))
    end
    
    should "convert between integers and hashes without encryption" do
      assert_equal 1001, UrlHash.from_hash(UrlHash.to_hash(1001))
    end
    
    should "correctly set the hash length" do
      assert_equal 8, UrlHash.to_hash(1001, :hash_length => 8).length
      assert_equal 12, UrlHash.to_hash(1001, :hash_length => 12).length
    end
    
    should "convert between integers and hashes with encryption" do
      options = {
        :key => Digest::SHA2.hexdigest('test key'), 
        :iv => Digest::SHA2.hexdigest('test initial value')
      }
      assert_equal 1001, UrlHash.from_hash(UrlHash.to_hash(1001, options), options)
    end
  end
end
