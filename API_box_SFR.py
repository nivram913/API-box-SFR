from flask import Flask, jsonify
from SFRBox import SFRBox

app = Flask(__name__)
base_url = "/boxapi/"

@app.route(base_url+'/reboot', methods=['POST'])
def reboot():
    box = SFRBox()
    if box.authenticate(password="secret") == -1:
        return jsonify({"status": "error", "error_message": "Authentication error"}), 401
    if box.reboot_gateway() == -1:
        return jsonify({"status": "error", "error_message": "Unknown error"}), 500
    return jsonify({"status": "success", "message": "Rebooting"}), 200

@app.route(base_url+'/port-forwarding', methods=['GET'])
def get_port_forwarding():
    box = SFRBox()
    if box.authenticate(password="secret") == -1:
        return jsonify({"status": "error", "error_message": "Authentication error"}), 401
    prt_frw_rules = box.get_port_forwarding_rules()
    box.logout()
    return jsonify(prt_frw_rules), 200

@app.route(base_url+'/port-forwarding', methods=['POST'])
def add_port_forwarding():
    box = SFRBox()
    if box.authenticate(password="secret") == -1:
        return jsonify({"status": "error", "error_message": "Authentication error"}), 401
    prt_frw_rules = box.get_port_forwarding_rules()
    if box.add_port_forwarding_rule(len(prt_frw_rules)+1, name, external_port, internal_port, protocol, dest_ip) == -1:
        return jsonify({"status": "error", "error_message": "Unknown error"}), 500
    box.logout()
    return jsonify({"status": "success", "message": "Rule added"}), 200

@app.route(base_url+'/port-forwarding', methods=['DELETE'])
def del_port_forwarding():
    box = SFRBox()
    if box.authenticate(password="secret") == -1:
        return jsonify({"status": "error", "error_message": "Authentication error"}), 401
    if box.del_port_forwarding_rule(number) == -1:
        return jsonify({"status": "error", "error_message": "Unknown error"}), 500
    box.logout()
    return jsonify({"status": "success", "message": "Rule deleted"}), 200

app.run()

