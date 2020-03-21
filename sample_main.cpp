#define OSC_NET_IGNORE_DEPRECATION_WARNINGS
#define OSC_NET_IMPLEMENTATION
#include "tinyosc-net.hpp"

#include "tinyosc.hpp"

#include <iostream>
#include <thread>

#define OSC_UDP_PORT_NUM_DEMO 9109

void open_udp_server()
{
    osc_net_address_t server_addr;
    osc_net_get_address(&server_addr, nullptr, OSC_UDP_PORT_NUM_DEMO);

    osc_net_socket_t server_socket;
    if (osc_net_udp_socket_open(&server_socket, server_addr, false))
    {
        std::cout << "osc_net_udp_socket_open osc_net_err: " << osc_net_get_error() << std::endl;
    }
    else
    {
        std::cout << ">>>>>>>>>>>>>>>>>> Server started, will listen to packets on UDP port " << OSC_UDP_PORT_NUM_DEMO << std::endl;

        tinyosc::osc_packet_reader packet_reader;
        tinyosc::osc_packet_writer packet_writer;

        while (true)
        {
            std::vector<uint8_t> recv_byte_buffer(1024 * 128);

            osc_net_address_t sender;
            if (auto bytes = osc_net_udp_socket_receive(&server_socket, &sender, recv_byte_buffer.data(), recv_byte_buffer.size(), 30))
            {
                packet_reader.initialize_from_ptr(recv_byte_buffer.data(), recv_byte_buffer.size());
                tinyosc::osc_message * msg;

                while (packet_reader.check_error() && (msg = packet_reader.pop_message()) != 0)
                {
                    int pingInt32Arg;
                    if (msg->match_complete("/ping").pop_int32(pingInt32Arg).check_no_more_args())
                    {
                        std::cout << "\tServer: received /ping " << pingInt32Arg << " from " << sender.host << "\n";

                        tinyosc::osc_message reply;
                        reply.initialize("/pong").push_int32(pingInt32Arg + 1);
                        packet_writer.reset().add_message(reply);

                        if (osc_net_udp_socket_send(&server_socket, sender, packet_writer.data(), packet_writer.size()))
                        {
                            std::cout << "osc_net_udp_socket_send osc_net_err: " << osc_net_get_error() << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << "Server: unhandled message: " << *msg << "\n";
                    }
                }
            }
        }
    }
}

void open_udp_client()
{
    osc_net_address_t local_addr;
    if (osc_net_get_address(&local_addr, "127.0.0.1", OSC_UDP_PORT_NUM_DEMO))
    {
        std::cout << "osc_net_get_address osc_net_err: " << osc_net_get_error() << std::endl;
    }

    osc_net_socket_t client_socket;
    if (osc_net_udp_socket_open(&client_socket, local_addr, false))
    {
        std::cout << "osc_net_udp_socket_open osc_net_err: " << osc_net_get_error() << std::endl;
    }
    else
    {
        std::cout << "Client started, will send packets to port " << OSC_UDP_PORT_NUM_DEMO << std::endl;

        int iping = 1;

        while (true)
        {
            tinyosc::osc_message msg("/ping");
            msg.push_int32(iping);

            tinyosc::osc_packet_writer packet_writer;
            packet_writer.start_bundle().start_bundle().add_message(msg).end_bundle().end_bundle();

            if (osc_net_udp_socket_send(&client_socket, local_addr, packet_writer.data(), packet_writer.size()))
            {
                std::cout << "osc_net_udp_socket_send osc_net_err: " << osc_net_get_error() << std::endl;
            }

            std::cout << "Client: sent /ping " << iping++ << "\n";

            std::vector<uint8_t> recv_byte_buffer(1024 * 128);

            osc_net_address_t sender;
            if (auto bytes = osc_net_udp_socket_receive(&client_socket, &sender, recv_byte_buffer.data(), recv_byte_buffer.size(),  30))
            {
                tinyosc::osc_packet_reader packet_reader(recv_byte_buffer.data(), recv_byte_buffer.size());
                tinyosc::osc_message * incoming_msg;
                while (packet_reader.check_error() && (incoming_msg = packet_reader.pop_message()) != 0)
                {
                    std::cout << "Client: received " << *incoming_msg << "(" << bytes << " bytes) \n";
                }
            }
            else
            {
                std::cout << "osc_net_udp_socket_receive osc_net_err: " << osc_net_get_error() << std::endl;
            }
        }

        //std::cout << "sock error: " << sock.errorMessage() << " -- is the server running?\n";
    }
}

void open_tcp_server()
{
    // @todo
}

void open_tcp_client()
{
    // @todo
}

int main(int argc, char * argv[])
{
    // Test instantiations of tinyosc objects
    tinyosc::osc_message msg;
    tinyosc::osc_packet_reader reader;
    tinyosc::osc_packet_writer writer;

    // Do platform-specific network stack bringup
    osc_net_init();

    std::thread server_thread = std::thread([]() {
        open_udp_server();
    });

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::thread client_thread = std::thread([]() {
        open_udp_client();
    });

    std::this_thread::sleep_for(std::chrono::seconds(20));

    server_thread.join();
    client_thread.join();

    // Do platform-specific network stack teardown 
    osc_net_shutdown();

    return 0;
}
