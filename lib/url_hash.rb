require 'openssl'
require 'base64'

module UrlHash
  DEFAULT_HASH_LENGTH = 8
  ALGORITHM = 'aes-256-cfb8'
  
  # convert an id (an integer) to a hash, a URL-compatible string.
  # 
  # for example. UrlHash.to_hash(1001) -> '+xDdeave3'
  #
  # options:
  #   :hash_length => how many characters to use for the hash. Defaults to 8.
  #     descreasing this increase the probability of a collision
  #   :key, :iv => provide these two options if you want to encrypt the hash.
  #     otherwise, it will relatively trivial for users to predict your hashes,
  #     and to work out ids based on them. Decide for yourself if this is a problem.
  #     It is recommended to generate them using Digest::SHA2.hexdigest.
  def self.to_hash(id, options = {})
    options = {:hash_length => DEFAULT_HASH_LENGTH}.merge(options)
    
    # buffers use all 256 bytes, hashes just 64, thus we can only use 3/4 the numbers
    #   -> 256 ** buffer_length <= 64 ** hash_length
    buffer_length = (3 * options[:hash_length] / 4).floor
    
    buffer = int_to_buffer(id, buffer_length)
    
    if (options.has_key? :key and options.has_key? :iv) 
      # encrypt the buffer
      buffer = self.encrypt(buffer, true, options)
    end
    
    # use -'s instead of + as we like that better
    Base64.encode64(buffer).tr("+", "-").strip
  end
  
  # convert an hash, as produced by to_hash, back into the original integer
  # 
  # for example. UrlHash.to_hash('+xDdeave3') -> 1001
  #
  # options:
  #   :key, :iv => provide these again if you are encrypting hashes
  def self.from_hash(hash, options = {})
    buffer = Base64.decode64(hash.tr("-", "+"))
    
    if (options.has_key? :key and options.has_key? :iv) 
      # encrypt the buffer
      buffer = self.encrypt(buffer, false, options)
    end
    
    buffer_to_int(buffer)
  end
  
private
  def self.encrypt(buffer, forward, options)
    c = OpenSSL::Cipher::Cipher.new(ALGORITHM)
    forward ? c.encrypt : c.decrypt
    c.key = options[:key]
    c.iv = options[:iv]

    e = c.update(buffer)
    e << c.final
  
    e
  end
  
  # turn a integer into a string representation.
  # we need to ensure that we use put the non-zero stuff on the
  # the MSB side so that it randomizes the string properly:
  # see : http://www.columbia.edu/~ariel/ssleay/fip81/fip81.html#td2
  def self.int_to_buffer(int, size)
    "".tap do |buf|
      size.times do
        buf << (int & 0xff)
        int /= 0x100
      end
    end
  end

  def self.buffer_to_int(buffer)
    int = 0
    multiplier = 1
    buffer.each_byte do |b|
      int += multiplier * b
      multiplier *= 0x100
    end
    
    int
  end
end