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
  $stdout.puts "#{device_vuln_id} #{vulns[device_vuln_id][:details].title} #{vulns[device_vuln_id][:details].cvss_score} #{vulns[device_vuln_id][:details].cvss_vector} affects: #{vulns[device_vuln_id][:affectsbyhost].length}"
  $stdout.puts "#{vulns[device_vuln_id][:affects].join(',')}"
end

# all_assets = nsc.assets.reduce({}) do |hash, dev|
#   $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address
#   hash[dev.address] = dev
#   hash
# end
# pp all_assets
#
exit 0
# # Get details of last report run.
# last = nsc.list_vulns(true)
# count = 0
# translate = {
#               "AV" => { "name" => "attack_vector",     "values" => { "L" => "local",    "A" => "adjacent", "N" => "network" } },
#               "AC" => { "name" => "access_complexity", "values" => { "H" => "high",     "M" => "medium",   "L" => "low"     } },
#               "Au" => { "name" => "authenticaiton",    "values" => { "M" => "multiple", "S" => "single",   "N" => "none"    } },
#               "C"  => { "name" => "confidentiality",   "values" => { "N" => "none",     "P" => "partial",  "C" => "complete"} },
#               "I"  => { "name" => "integrity",         "values" => { "N" => "none",     "P" => "partial",  "C" => "complete"} },
#               "A"  => { "name" => "availability",      "values" => { "N" => "none",     "P" => "partial",  "C" => "complete"} }
#             }
# last.each do |vuln|
#   PP.pp vuln.class
#   # :added, :credentials, :cvss_score, :cvss_vector, :id, :modified, :pci_severity, :published, :safe, :severity, :title
#   if vuln.severity >= 10
#     next if count > 5
#     puts "#{vuln.severity}: #{vuln.title}" 
#     count += 1
#     #  :added, :credentials, :cvss_score, :cvss_vector, :description, :id, :modified, :pci_severity, :published, :references, :safe, :severity, :solution, :title
#     details = nsc.vuln_details(vuln.id)
#     vector_string = details.cvss_vector
#     score_metrics = Hash.new()
#     vector_string.gsub(/[\(\)]/,'').split(/\//).each do |metric|
#       (key,value) = metric.split(/:/)
#       score_metrics[ translate[key]["name"] ] = translate[key]["values"][value]
#     end
#     puts "#{details.cvss_score} #{details.cvss_vector}"
#     puts "Attack Vector     :  #{score_metrics["attack_vector"]}"
#     puts "Attack Complexity :  #{score_metrics["attack_complexity"]}"
#     puts "Authentication    :  #{score_metrics["authentication"]}"
#     puts "Confidentiality   :  #{score_metrics["confidentiality"]}"
#     puts "Integrity         :  #{score_metrics["integrity"]}"
#     puts "Availability      :  #{score_metrics["availibility"]}"
#   end
# end
