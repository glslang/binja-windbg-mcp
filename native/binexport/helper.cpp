// The processor is based on the pinned MIT-licensed BN6 SDK and carries the
// narrowly scoped CLRBHB compatibility fallback documented in this directory.
#include "processor.h"
#include "third_party/zynamics/binexport/binexport2.pb.h"
#include "json/json.h"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace {
std::mutex exportMutex;
constexpr uintmax_t maxExportBytes = 256 * 1024 * 1024;
char* Response(const Json::Value& value)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return strdup(Json::writeString(builder, value).c_str());
}
}

extern "C" {
__attribute__((visibility("default"))) uint32_t BNMCPExportABI() { return 1; }
__attribute__((visibility("default"))) uint32_t BNMCPCoreABI() { return BN_CURRENT_CORE_ABI_VERSION; }
__attribute__((visibility("default"))) void BNMCPFree(void* value) { free(value); }

// Caller keeps the view and callback alive until this synchronous call returns.
__attribute__((visibility("default"))) char* BNMCPExportView(
    BNBinaryView* rawView, const char* destination, const char* exportId, bool (*keepGoing)())
{
    Json::Value response;
    try {
        if (!rawView || !destination || !exportId || !keepGoing)
            throw std::runtime_error("Invalid export arguments");
        if (!BNIsUIEnabled() || BNGetCurrentCoreABIVersion() != BN_CURRENT_CORE_ABI_VERSION)
            throw std::runtime_error("Export requires a compatible running Binary Ninja GUI");
        std::lock_guard<std::mutex> lock(exportMutex);
        BinaryNinja::Ref<BinaryNinja::BinaryView> view =
            new BinaryNinja::BinaryView(BNNewViewReference(rawView));
        {
            BinDiffProcessor processor(*view);
            for (const auto& function : view->GetAnalysisFunctionList()) {
                if (!keepGoing()) throw std::runtime_error("Export cancelled");
                processor.AddFunction(*function);
            }
            if (!processor.Process(destination, [&](double) { return keepGoing(); }))
                throw std::runtime_error("BinExport failed or was cancelled");
        }
        if (!keepGoing()) throw std::runtime_error("Export cancelled");
        if (std::filesystem::file_size(destination) > maxExportBytes)
            throw std::runtime_error("BinExport exceeds 256 MiB");
        BinExport2 proto;
        std::ifstream input(destination, std::ios::binary);
        if (!proto.ParseFromIstream(&input)) throw std::runtime_error("Invalid BinExport output");
        input.close();
        // BinExport's application-defined executable_id binds even identical builds
        // to their input slot; the processor otherwise writes a placeholder hash.
        proto.mutable_meta_information()->set_executable_id(exportId);
        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        if (!proto.SerializeToOstream(&output)) throw std::runtime_error("BinExport write failed");
        output.close();
        if (!output) throw std::runtime_error("BinExport close failed");
        response["export_id"] = exportId;
        response["architecture"] = proto.meta_information().architecture_name();
        response["functions"] = Json::Value(Json::arrayValue);
        std::vector<uint64_t> addresses;
        uint64_t next = 0;
        for (const auto& instruction : proto.instruction()) {
            uint64_t address = instruction.has_address() ? instruction.address() : next;
            addresses.push_back(address);
            next = address + instruction.raw_bytes().size();
        }
        for (const auto& graph : proto.flow_graph()) {
            const auto& block = proto.basic_block(graph.entry_basic_block_index());
            if (block.instruction_index_size() == 0) continue;
            auto index = block.instruction_index(0).begin_index();
            response["functions"].append(fmt::format("0x{:016x}", addresses.at(index)));
        }
        response["ok"] = true;
    } catch (const std::exception& error) {
        response["ok"] = false;
        response["error"] = error.what();
    } catch (...) {
        response["ok"] = false;
        response["error"] = "Unknown export failure";
    }
    return Response(response);
}
}
