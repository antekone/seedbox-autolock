require 'openssl'
require 'socket'
require 'base64'

hosts = [
	{ :host => "localhost", :port => 9293 },
	{ :host => "localhost", :port => 9293 },
	{ :host => "localhost", :port => 9293 },
	{ :host => "localhost", :port => 9293 },
	{ :host => "localhost", :port => 9293 },
	{ :host => "localhost", :port => 9293 },
]

pubKey = OpenSSL::PKey::DSA.new(File.read("public.pem"))

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

def tryHost(host, port, pubKey)
	sock = TCPSocket.new(host, port)
	r = Random.new()

	str = (0..128).to_a().map() { |i| r.rand(10000) }.join()
	str2 = (0..128).to_a().map() { |i| r.rand(10000) }.join()
	fstr = "#{str}#{str2}"

	sock.write([fstr.size()].pack("L"))
	sock.write(fstr)

	sha = OpenSSL::Digest::SHA1.digest(fstr)

	len = sock.read(4).unpack("L")[0]
	sig = readBytes(sock, len)

	sig = Base64::strict_decode64(sig)
	f = pubKey.sysverify(sha, sig)

	sock.close()
	return f
rescue StandardError => e
	puts(e)
	return false
end

failedHosts = 0
hosts.each() do |host|
	failedHosts += 1 if not tryHost(host[:host], host[:port], pubKey)
end

if failedHosts == hosts.size()
	puts("suspend luks")
end
