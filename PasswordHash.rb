require 'digest/md5'

class PasswordHash
	def initialize(iteration_count_log2, portable_hashes)
		@itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

		if iteration_count_log2 < 4 or iteration_count_log2 > 31
			iteration_count_log2 = 8
		end

		@iteration_count_log2 = iteration_count_log2
		@portable_hashes      = portable_hashes
		@random_state         = Time.now.to_f.to_s + rand().to_s
	end

	def get_random_bytes(count)
		output = ''
		random = File.new('/dev/random', 'r')

		if random
			str    = random.read(count)
			output += str

			random.close
		end

		if output.length < count
			output = ''
			i      = 0

			until i < count
				@random_state = Digest::MD5.hexdigest Time.now.to_f.to_s + @random_state

				output += [Digest::MD5.hexdigest(@random_state)].pack 'H*'

				i += 16
			end

			output = output[0..count]
		end

		return output
	end

	def encode64(input, count)
		output = ''
		i      = 0

		while i < count
			value  = input[i].ord
			output += @itoa64[value & 0x3f]

			i += 1

			if i < count
				value = value | input[i].ord << 8
			end

			output += @itoa64[(value >> 6) & 0x3f]

			if i >= count
				break
			end

			i += 1

			if i < count
				value = value | input[i].ord << 16
			end

			output += @itoa64[(value >> 12) & 0x3f]

			if i >= count
				break
			end

			i += 1

			output += @itoa64[(value >> 18) & 0x3f]
		end

		return output
	end

	def gensalt_private(input)
		output = '$P$'
		output += @itoa64[[@iteration_count_log2 + 5, 30].min]
		output += self.encode64(input, 6)

		return output
	end

	def crypt_private(password, setting)
		output = '*0'

		if setting[0, 2] == output
			output = '*1'
		end

		id = setting[0, 3]

		if id != '$P$' and id != '$H$'
			return output
		end

		count_log2 = @itoa64.index setting[3]

		if count_log2 < 7 or count_log2 > 30
			return output
		end

		count = 1 << count_log2
		salt  = setting[4, 8]

		if salt.length != 8
			return output
		end

		hash = Digest::MD5.digest salt + password

		while count > 0
			hash = Digest::MD5.digest hash + password

			count -= 1
		end

		output = setting[0, 12]
		output += self.encode64(hash, 16)

		return output
	end

	def hash(password)
		random = ''

		if random.length < 6
			random = self.get_random_bytes 6
		end

		hash = self.crypt_private password, self.gensalt_private(random)

		if hash.length == 34
			return hash
		end

		# Returning '*' on error is safe here, but would _not_ be safe
		# in a crypt(3)-like function used _both_ for generating new
		# hashes and for validating passwords against existing hashes.
		return '*'
	end

	def check(password, stored_hash)
		hash = self.crypt_private password, stored_hash

		if hash[0] == '*'
			return false
		end

		return hash == stored_hash
	end
end

# Testing
ph = PasswordHash.new 8, true

test = ph.hash 'dsfsdf'

puts test
puts ph.check 'dsfsdf', test