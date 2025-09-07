#include "Util/Logger/Logger.hpp"
#include "Version.hpp"
#include "Hooks/Fixes.hpp"

SKSEPluginLoad(const LoadInterface * a_SKSE) {

	Init(a_SKSE);

	logger::Initialize();
	logger::SetLevel("Trace");
	BingusFixes::Install();

	logger::info("SKSEPluginLoad OK");

	return true;
}

SKSEPluginInfo(
	.Version = Plugin::ModVersion,
	.Name = Plugin::ModName,
	.Author = "BingusEx",
	.StructCompatibility = SKSE::StructCompatibility::Independent,
	.RuntimeCompatibility = SKSE::RUNTIME_SSE_1_6_1170
);