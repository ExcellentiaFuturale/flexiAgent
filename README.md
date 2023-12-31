# flexiWAN Official Repository

The official respository for flexiwan is in https://gitlab.com/flexiwangroup

# About flexiWAN

flexiWAN is the world's first open source [SD-WAN](https://flexiwan.com/). flexiWAN offers a complete SD-WAN solution comprising of flexiEdge (the edge router) and flexiManage (the central management system) with core SD-WAN functionality. Our mission is to democratize the SD-WAN Market through an open source & modular  SD-WAN solution lowering barriers to entry for companies to adopt it or offer services based on the flexiWAN SD-WAN solution. To learn more about the flexiWAN's unique approach to networking, visit the [flexiWAN](https://flexiwan.com/) website, and follow the company on [Twitter](https://twitter.com/FlexiWan) and [LinkedIn](https://www.linkedin.com/company/flexiwan).

To contact us please drop us an email at yourfriends@flexiwan.com, or for any general issue please use our [Google User Group](https://groups.google.com/a/flexiwan.com/forum/#!forum/flexiwan-users)

# flexiAgent

This repository contains the flexiWAN Agent component. flexiAgent is responsible to communicate with flexiManage.
flexiWAN Agent connects with the flexiWAN management using a bi-directional secured web socket connection for configuration and statistics. 
The flexiWAN Agent supports the capabilities of:

* Get simplified JSON API commands
* Separate and translate APIs into internal commands provisioned in Linux and the Router
* Key-value configuration storage
* Orchestrate the execution sequence between various elements
* Restore the last system state and configuration after reboot
* Transaction configuration processing and roll-back on failures
* Monitor components and restart them on failure
* Provide JSON structure of the entire configuration
* Provide various CLI commands for troubleshooting

