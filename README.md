# Networks_Capture_analysyis
In today's interconnected world, networks form the backbone of digital communication, enabling seamless data exchange across diverse systems. While data science focuses on analyzing, interpreting, and extracting insights from data, computer networking ensures the smooth transfer of this data through robust and efficient infrastructures. This project sought to bridge these two fields by leveraging data science methodologies to monitor and analyze real-time network activity.
The goal of this project aims to improve network security and performance by means of a network monitoring system that records real-time packet data. The first component is configuring a Python packet sniffing mechanism with the scapy module to capture and document important packet information including protocol type, source and destination addresses, and packet size. The second part of the system is then formed by precisely timed logs of these elements into a file. Constant storage of this data allows the logging system to produce a consistent, time-stamped record of network activities. With this log, network managers may effectively troubleshoot problems, spot abnormalities, and examine data trends. Apart from that, the kept records are a great tool for spotting any security risks and tracking illegal behavior. This twin technique guarantees thorough monitoring of network traffic, therefore supporting a safe, high-performance network environment.g.

# results- Console output


After the server starts sniffing , the system will print the throughput calculations every 10 seconds , the network metrics (requirement 6) and summery stats ( requirement 7) every 30 seconds.
To obey by this tight printing schedule on a shared resource ( the console) we used multi threading technique such as locks

![image](https://github.com/user-attachments/assets/4eb51431-38ac-4824-8880-48bd5374ffe6)

![image](https://github.com/user-attachments/assets/8124f265-7114-4561-a9c0-a3ae4cf65609)


# results- visualizations charts

upon termination (CTRL+Q) the system will output 3 visualizations as required, the input data for each one of them will be read from our events log file , Reading data in real time and figuring out the best formatting practice was a challenge we were happy to tackle .
other than requirements, we wanted to add a little touch of our backgrounds as data analysts with the sns library to make the visualizations appealing.

![latency_distribution](https://github.com/user-attachments/assets/4164eb23-42aa-43a2-950d-5c70274a3766)

3-Latency Distribution
our latency graph helps us understand patterns in the connection delays of our system.
the graph shows significant variance in the average connection latency, from 100 ms to over 600 ms. this variance may be due networks congestion , different packet sizes or handling different protocol requirement, it would be interesting to deploy this project and explore this variance more over a broader network.  
key points to keep in mind regarding the variance in the average latency :

TCP exhibits higher latency due to its acknowledgment mechanisms and retransmissions, meanwhile UDP's has usually lower latency due to its requirement ( no hand shaking or acknowledgment ), this naturally caused our average latency to vary.
Our graph also highlights how congestion in the network can affect protocols like TCP, where retransmissions are required for lost or delayed packets, this doesn’t pose as much of an issue for it’s UDP counter part.

what we can conclude from this graph is that applying this system to a higher scalability could be challenging , to fully understand and address this, we recommend once again deploying the system over a broader range of devices.


![protocol_usage_updated](https://github.com/user-attachments/assets/0da9a306-05ce-4e23-bd38-cdee23f497c5)

2- Protocol Usage and Unique Entities
Our bar chart highlights the frequency of and diversity of each protocol in our test network.
 TCP predominance:
proving true to the throughput spikes in the previous chart with over 140,000 instances ,TCP is the most frequently used protocol in our test case, which is expected due to its high reliability for data transmission.
Ethernet:
coming seconds once again, Ethernet protocols also show significant activity, confirming our correlation theory mentioned earlier regarding its foundational role in delivering TCP traffic.

UDP:
UDP has fewer occurrences around 2442 packets during our testing, which is due to being likely not as needed during the timing, as UDP specializes in lightweight cases such as streaming as previously mentioned.

Unique IPs and MACs: 
The low counts of unique IP addresses (49) and MAC addresses (34) are likely due to our relatively small network size ( since the testing was done on one device with many connections)

we can conclude that over all for this testing ,  TCP has been playing an important rule , dominating the network due to it’s reliability, while UDP is more niche and rare. 

 

![throughput_over_time](https://github.com/user-attachments/assets/0e896477-e6bb-426b-ada3-9ad176526a35)

1- Throughput over time 

visualizing the throughput over time for each run provided interesting insights into network traffic across the different protocols we are mentoring.
For this specific test run , key observations are:

 TCP predominance:
the TCP  protocol showed the highest throughput spikes between our protocols. we can come to the conclusion that it has a very noticeable rule in our test network.
Ethernet:
coming seconds in significant in our network is ethernet, we can notice interestingly that the existence of ethernets is at its highest with TCP. This correlation could indicates a dependency on Ethernet infrastructure for TCP data transmission.
UDP and IP impact:
unlike the previous TCP and ethernet , UDP and IP show significantly lower throughout levels, after doing some research , this is to be expected since UDP is generally used for smaller less frequents packets, such as DNS queries or media streaming . 


 # Conclusion
 
This project was a rewarding intersection of data science and computer networking, merging our analytical expertise with the challenges of understanding real-time systems. It pushed us beyond the boundaries of static data analysis, requiring us to adapt our skills to the dynamic and unpredictable nature of network traffic. From designing a client-server architecture to analyzing latency and throughput, each step enhanced our understanding of how data flows and how networks operate in real-world scenarios.
The experience underscored the value of interdisciplinary learning, showing how data science principles like feature engineering, trend analysis, and visualization can enhance domains like networking. By treating packets as streaming datasets and leveraging data-driven insights, we successfully bridged the gap between two fields, creating a system that monitors and interprets network behavior effectively.


"Data is the new oil, and networks are the pipelines that deliver its value to the world."  


# Work done by:

Rinad Almjishai  & Deema Alharbi



