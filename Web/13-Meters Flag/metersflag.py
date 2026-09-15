from flask import Flask, request, render_template
from lxml import etree

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/', methods=['POST'])
def calculate_bmi():
    xml_data = request.data
    
    if b"<!DOCTYPE" in xml_data or b"+ADwAIQ-ENTITY" in xml_data:
        return "I'm watching you *-*"
    
    try:
        parser = etree.XMLParser(resolve_entities=True)
        doc = etree.fromstring(xml_data, parser)
        weight = doc.xpath('//weight/text()')[0]
        height = doc.xpath('//height/text()')[0]

        bmi = calculate_bmi(weight, height)
        bmi_category = get_bmi_category(bmi)

        xml_response = f"<response><height>{height}</height><weight>{weight}</weight><result>BMI: {bmi:.2f} ({bmi_category})</result></response>"

        return xml_response, {'Content-Type': 'application/xml'}

    except etree.XMLSyntaxError as e:
        return 'Invalid XML data', 400


def calculate_bmi(weight, height):
    try:
        weight_float = float(weight)
    except ValueError:
        weight_float = 0.0
    
    try:
        height_float = float(height)
    except ValueError:
        height_float = 0.0

    height_in_meters = height_float / 100  # Convert height to meters
    return weight_float / (height_in_meters * height_in_meters)


def get_bmi_category(bmi):
    if bmi < 18.5:
        return 'Underweight'
    elif 18.5 <= bmi < 25:
        return 'Normal weight'
    elif 25 <= bmi < 30:
        return 'Overweight'
    else:
        return 'Obese'


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=False)