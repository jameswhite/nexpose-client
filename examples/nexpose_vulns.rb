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
  nsc.list_site_devices(site.id).each do |asset|
    hostname = nsc.asset_scan_history(asset.id).last.host_name
    $stderr.puts "  #{hostname} (#{asset.address}):" 
    nsc.list_device_vulns(asset.id).each do |device_vuln|
      if vulns[device_vuln.id].nil?
        vulns[device_vuln.id] = Hash.new()
        vulns[device_vuln.id][:details] = nsc.vuln_details(device_vuln.id)
        vulns[device_vuln.id][:affects] = Array.new()
        vulns[device_vuln.id][:affectsbyip] = Array.new()
        vulns[device_vuln.id][:affectsbyhost] = Array.new()
      end
      vulns[device_vuln.id][:affects].push("#{hostname} (#{asset.address})") unless vulns[device_vuln.id][:affects].include?("#{hostname} (#{asset.address})")
      vulns[device_vuln.id][:affectsbyip].push(asset.address) unless vulns[device_vuln.id][:affectsbyip].include?(asset.address)
      vulns[device_vuln.id][:affectsbyhost].push(hostname) unless vulns[device_vuln.id][:affectsbyhost].include?(hostname)
      $stderr.puts "    #{device_vuln.id} #{vulns[device_vuln.id][:details].title} #{vulns[device_vuln.id][:details].cvss_score} #{vulns[device_vuln.id][:details].cvss_vector}"
    end
  end
end

vulns.keys each do |v|
  $stdout.puts "#{device_vuln.id} #{vulns[device_vuln.id][:details].title} #{vulns[device_vuln.id][:details].cvss_score} #{vulns[device_vuln.id][:details].cvss_vector} affects: #{vulns[device_vuln.id][:affectsbyhost].length}"
  $stdout.puts "#{vulns[device_vuln.id][:affects].join(',')}"
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
