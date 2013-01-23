require 'openssl'
require 'socket'
require 'base64'
require 'timeout'

def loadHosts(config)
	hosts = []
	IO.readlines(config).each() do |line|
		host,port,pem = line.strip().split(":")
		hosts << { :host => host, :port => port, :pem => pem }
	end
	hosts
rescue StandardError => e
	puts("Syntax error in config file: #{e}")
	return nil
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

def doTryHost(host, port, pubKey)
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
	return false
end

def tryHost(host, port, pubKey)
	timeout(10) do
		doTryHost(host, port, pubKey)
	end
rescue Timeout::Error
	return false
end

hosts = loadHosts("hosts.conf")
if hosts == nil or hosts.size() == 0
	puts("Can't load configuration: hosts.conf")
	exit(1)
end

failedHosts = 0
hosts.each() do |host|
	pubKey = OpenSSL::PKey::DSA.new(File.read(host[:pem]))
	failedHosts += 1 if not tryHost(host[:host], host[:port], pubKey)
end

if failedHosts == hosts.size()
	`./error.sh`
else
	`./ok.sh`
end
