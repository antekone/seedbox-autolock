require 'openssl'
require 'socket'
require 'base64'

class Node
	def initialize()
		if not File.exists?("private.pem")
			@privKey = OpenSSL::PKey::DSA.new(4096)
			File.write("private.pem", @privKey.to_pem())
		else
			@privKey = OpenSSL::PKey::DSA.new(File.read("private.pem"))
		end

		pubKey = @privKey.public_key
		File.write("public.pem", pubKey.to_pem()) if not File.exists?("public.pem")
	end

	def run(port)
		sock = TCPServer.new("0.0.0.0", port)
		loop do
			s = sock.accept()
			handle(s)
			s.close()
		end
	end

	def readBytes(sock, len)
		togo = len
		arr = []
		while(togo > 0)
			data = sock.read(togo)
			togo -= data.size()
			arr << data
		end
		arr.join()
	end

	def handle(s)
		len = s.read(4).unpack("L")[0]
		return if len > 2048 or len < 63
		data = readBytes(s, len)

		sha = OpenSSL::Digest::SHA1.digest(data)
		sig = @privKey.syssign(sha)
		b64 = Base64::strict_encode64(sig)
		s.write([b64.size()].pack("L"))
		s.write(b64)
	rescue StandardError => e
		puts(e)
	end
end
