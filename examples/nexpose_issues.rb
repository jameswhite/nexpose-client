#!/usr/bin/env ruby
require 'pp'
require 'nexpose'
include Nexpose

nsc = Connection.new(ENV['NEXPOSE_HOST'],ENV['NEXPOSE_USER'],ENV['NEXPOSE_PASS'],ENV['NEXPOSE_PORT'])
nsc.login
at_exit { nsc.logout }

vulns = Hash.new() # cache these to avoid repeat lookups
nsc.sites.each do |site|
  $stderr.puts "[#{site.name}]"
  count = 0
  # Loop through the assets (hosts, switches, etc.) and list their vulns, and make a hash with a key of the vuln with a list of the hosts
  nsc.list_site_devices(site.id).each do |asset|
    next if count > 10 # 10 per site until we get a good run
    count += count + 1
    hostname = nsc.asset_scan_history(asset.id).last.host_name
    $stderr.puts "  #{hostname} (#{asset.address}):"
    nsc.list_device_vulns(asset.id).each do |device_vuln|
      # Create the new vulnerabilty entry if we haven't seen it before
      if vulns[device_vuln.id].nil?
        vulns[device_vuln.id] = Hash.new()
        vulns[device_vuln.id][:details] = nsc.vuln_details(device_vuln.id)
        vulns[device_vuln.id][:affects] = Array.new()
        vulns[device_vuln.id][:affectsbyip] = Array.new()
        vulns[device_vuln.id][:affectsbyhost] = Array.new()
      end
      # collect the hosts as hostname, IP, and hostname(IP); hostname is what the last scan saw, not what's actually in DNS
      vulns[device_vuln.id][:affects].push("#{hostname} (#{asset.address})") unless vulns[device_vuln.id][:affects].include?("#{hostname} (#{asset.address})")
      vulns[device_vuln.id][:affectsbyip].push(asset.address) unless vulns[device_vuln.id][:affectsbyip].include?(asset.address)
      vulns[device_vuln.id][:affectsbyhost].push(hostname) unless vulns[device_vuln.id][:affectsbyhost].include?(hostname)
      $stderr.puts "    #{device_vuln.id} #{vulns[device_vuln.id][:details].title} #{vulns[device_vuln.id][:details].cvss_score} #{vulns[device_vuln.id][:details].cvss_vector}"
    end
  end
end

# Now go through all the vulns, print a summary on one line and the affected hostnames(IPs) on the line that follows
vulns.keys.each do |device_vuln_id|
  $stdout.puts "vulnerability: #{device_vuln_id} #{vulns[device_vuln_id][:details].title} #{vulns[device_vuln_id][:details].cvss_score} #{vulns[device_vuln_id][:details].cvss_vector} affects: #{vulns[device_vuln_id][:affectsbyhost].length}"
  $stdout.puts "affects: #{vulns[device_vuln_id][:affects].join(',')}"
  $stdout.puts
end
