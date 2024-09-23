#!/usr/bin/node

import { basename } from "path";
import { readFileSync, writeFileSync } from "fs";
import { execSync } from "child_process";
import { fileURLToPath } from "url";
import { EOL } from "os";

const Stage = {
    PreStart: "pre-start",
    PreStop: "pre-stop",
    PostStart: "post-start",
    PostStop: "post-stop",
};

function readJSONFile(filepath) {
    try {
        const data = readFileSync(filepath, "utf8");
        return JSON.parse(data);
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}

function writeJSONFile(filepath, data) {
    try {
        const newData = JSON.stringify(data, null, 2) + EOL;
        writeFileSync(filepath, newData, "utf8");
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}

function executeCommand(command) {
    try {
        return execSync(command, {
            encoding: "utf8",
        }).trim();
    } catch (error) {
        console.log(error);
        process.exit(1);
    }
}

function handleCore(options, customConfig) {
    const { stage, v2rayaConfdir } = options;

    switch (stage) {
        case Stage.PreStart:
            const configPath = `${v2rayaConfdir}/config.json`;
            const configData = readJSONFile(configPath);

            configData.inbounds.forEach((inbound) => {
                if (/transparent/.test(inbound.tag)) {
                    inbound.sniffing.destOverride.push("fakedns");
                }
            });

            // 部分域名不使用fakeip
            // 需要在 设置 -> 防止DNS污染 -> 自定义高级设置 -> 域名查询服务器 进行配置，外国域名查询服务器留空
            configData.dns.servers?.forEach((server) => {
                server.domains = customConfig.fake_dns_exclude_domains;
            });

            configData.dns.servers?.unshift({
                address: "fakedns",
            });

            configData.dns.domainMatcher = "mph";

            configData.routing.domainStrategy = "IpIfNonMatch";

            writeJSONFile(configPath, configData);

            console.log(`v2rayA core hook ${stage} finished`);

            break;

        default:
            break;
    }
}

function handleTransparent(options, customConfig) {
    const { stage } = options;

    switch (stage) {
        case Stage.PostStart:
            const nftTables = executeCommand("nft list tables");

            if (/v2raya/.test(nftTables)) {
                executeCommand(
                    `nft insert rule inet v2raya tp_rule meta skuid {${customConfig.bypass_users.join(", ")}} return`
                );

                const commonPorts = customConfig.common_ports.join(", ");
                executeCommand(
                    `nft insert rule inet v2raya tp_rule tcp dport != {${commonPorts}} return`
                );
                executeCommand(
                    `nft insert rule inet v2raya tp_rule udp dport != {${commonPorts}} return`
                );
            }
            console.log(`v2rayA transparent hook ${stage} finished`);
            break;

        default:
            break;
    }
}

function parseArgument(argv) {
    let transparentType = null;
    let stage = null;
    let v2rayaConfdir = null;

    argv.slice(2).forEach((arg) => {
        const [key, val] = arg.split("=");
        switch (key) {
            case "--stage":
                stage = val;
                break;
            case "--transparent-type":
                transparentType = val;
                break;
            case "--v2raya-confdir":
                v2rayaConfdir = val;
                break;
            default:
                console.log(`Unknown argument: ${arg}`);
                break;
        }
    });

    return {
        transparentType,
        stage,
        v2rayaConfdir,
    };
}

function main() {
    const scriptName = basename(fileURLToPath(import.meta.url));

    const options = parseArgument(process.argv);

    const customConfig = readJSONFile(
        `${options.v2rayaConfdir}/custom_config.json`
    );

    switch (scriptName) {
        case "v2raya-core-hook":
            handleCore(options, customConfig);
            break;
        case "v2raya-transparent-hook":
            handleTransparent(options, customConfig);
            break;
        default:
            break;
    }
}

main();
