package example

import rego.v1

default allow := false
default allow_data := false

allow if {
	count(violation) == 0
}

allow_data if {
	count(violation_data) == 0
}


violation contains server.id if {
	some server
	public_servers[server]
	server.protocols[_] == "http"
    server.protocols[_] == "https"
}

violation contains server.id if {
	server := input.servers[_]
	server.protocols[_] == "telnet"
}

public_servers contains server if {
	some i, j
	server := input.servers[_]
	server.ports[_] == input.ports[i].id
	input.ports[i].network == input.networks[j].id
	input.networks[j].public
}


public_servers_data contains server_data if {
	some i, j
	server_data := data.servers[_]
	server_data.ports[_] == data.ports[i].id
	data.ports[i].network == data.networks[j].id
	data.networks[j].public
}

violation_data contains server_data.id if {
	some server_data
	public_servers_data[server_data]
	server_data.protocols[_] == input.server
}


