// Configure and run Pulsar authority, clock sampling, and orderly process shutdown.
#include "process.hpp"
#include "server.hpp"

#include <iostream>

// Process entry point; configuration errors and runtime failures have distinct exit codes.
int main(int argc, char** argv) {

    try {
        if (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h")) {
            std::cout << astra::Server::Config::help();
            return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--version") {
            std::cout << "pulsar 0.1.0 (C++26, gRPC v1)\n";
            return 0;
        }

        std::vector<std::string_view> arguments;
        for (int i = 1; i < argc; ++i) {
            arguments.emplace_back(argv[i]);
        }

        auto config = astra::Server::Config::parse(arguments);
        if (!config) {
            std::cerr << config.error().message << '\n';
            return 2;
        }

        astra::Signals signals;

        astra::Logger logger("pulsar");

        astra::Server server(std::move(*config));
        server.start();
        logger.write("started", "{\"admission\":" + astra::jsonString(server.admissionEndpoint()) + ",\"pulse\":" + astra::jsonString(server.pulseEndpoint()) + "}");

        astra::Wakeup wake;

        bool reportedSynchronized = false;
        // Use local monotonic time for log throttling, independently of published Unix time.
        auto nextReport = astra::Steady::now();
        while (!signals.requested()) {

            const auto local = astra::Steady::now();
            if (local >= nextReport) {
                // Report clock quality once per second, including initial calibration. Reference failure does not stop admission service.
                const auto time = server.time();
                // A running local clock alone is insufficient to serve trusted time samples.
                const bool synchronized = time && time->synchronized;
                if (synchronized != reportedSynchronized) {
                    reportedSynchronized = synchronized;
                    logger.write(synchronized ? "clock_synchronized" : time ? "clock_holdover"
                                                                            : "clock_unavailable");
                }
                logger.write("clock_status", time ? std::string("{\"ready\":") + (time->ready ? "true" : "false") + ",\"synchronized\":" + (synchronized ? "true" : "false") + ",\"nanoseconds\":" + std::to_string(time->time.time_since_epoch().count()) + ",\"uncertainty_ns\":" + std::to_string(time->uncertaintyNanoseconds) + "}" : "{\"ready\":false,\"synchronized\":false}");
                nextReport = local + std::chrono::seconds(1);
            }
            wake.wait(wake.observe());
        }
        server.stop();
        logger.write("stopped");
        return 0;
    } catch (...) {
        std::cerr << "Pulsar failed to start or operate; check configuration, identity, ports and database\n";
        return 1;
    }
}
