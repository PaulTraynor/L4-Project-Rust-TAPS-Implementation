## Running the code 

To run the code in an existing project, the minimum set of imports required are as follows:

	use taps::endpoint::RemoteEndpoint::HostnamePort;
	use taps::pre_connection::PreConnection;
	use taps::transport_properties::TransportProperties;	
	
Then create a PreConnection from default TransportProperties and a RemoteEndpoint as follows:

	let mut t_ps = TransportProperties::default();
	let r_e = RemoteEndpoint::HostnamePort("www.google.com".to_string(), 443);
	let mut p_c_client = PreConnection::new(None, Some(r_e), t_ps, None);

To generate a Connection to the remote host, call initiate() on the PreConnection:

	let conn = p_c_client.initiate().await.unwrap();