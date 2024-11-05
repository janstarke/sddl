import { useId, useState, Fragment } from 'react'

import { convert } from "sddl4web";
import Button from "react-bootstrap/Button";
import Form from 'react-bootstrap/Form';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Alert from 'react-bootstrap/Alert';
import Tab from 'react-bootstrap/Tab';
import Tabs from 'react-bootstrap/Tabs';
import Table from 'react-bootstrap/Table';
import 'bootstrap/dist/css/bootstrap.min.css';
import { JsonView, allExpanded, darkStyles, defaultStyles } from 'react-json-view-lite';

function App() {
  const [count, setCount] = useState(0)
  const [sddl, setSddl] = useState('O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)');
  const [sid, setSid] = useState('S-1-5-21-1004336348-1177238915-682003330-512');
  const [json, setJson] = useState(null);
  const [lastError, setLastError] = useState(null);

  const [owner, setOwner] = useState('');
  const [group, setGroup] = useState('');
  const [flags, setFlags] = useState('');
  const [dacl, setDacl] = useState(null);
  const [sacl, setSacl] = useState(null);

  function handleSddlChange(e) {
    setSddl(e.target.value);
  }

  function handleSidChange(e) {
    setSid(e.target.value);
  }

  function convertSddl() {
    try {
      const json = JSON.parse(convert(sddl, sid))
      setJson(json);
      setOwner(json.owner);
      setGroup(json.owner);
      setFlags(json.flags);
      setDacl(json.dacl);
      setSacl(json.sacl);

      setLastError(null);
    } catch (e) {
      setLastError(e);
      setJson(null);
    }
  }

  function label_and_text(label, text) {
    return (
      <Form.Group as={Row} className="mb-3" >
        <Form.Label column sm={2}>{label}</Form.Label>
        <Col sm={10}>
          <Form.Control type="text" value={text} readOnly />
        </Col>
      </Form.Group>
    )
  }

  function ace_table_line(ace) {
    const ace_type = Object.entries(ace)[0][0];
    const ace_data = Object.entries(ace)[0][1];
    return (
      <tr>
        <td>{ace_type}</td>
        <td>{ace_data.header.ace_flags}</td>
        <td>{ace_data.header.mask}</td>
        <td>{ace_data.sid}</td>
      </tr>
    )
  }

  function acl_list(acl) {
    const listItems = acl.ace_list.map(ace_table_line);

    return (
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>ACE Type</th>
            <th>Flags</th>
            <th>Mask</th>
            <th>Sid</th>
          </tr>
        </thead>
        <tbody>
          {listItems}
        </tbody>
      </Table>
    );
  }

  return (
    <>
      <div className="container py-4 px-3 mx-auto">
      <h1>Online SDDL Decoder</h1>
        <Form>
          <Form.Group className="mb-3">
            <Row className="mb-3">
              <Form.Group>
                <Form.Label>SDDL String</Form.Label>
                <Form.Control type="text" aria-describedby="sddlHelpBlock" value={sddl} onChange={handleSddlChange} />
                <Form.Text id="sddlHelpBlock" muted>
                  Place some SDDL (Security Descriptor Description Language) string
                </Form.Text>
              </Form.Group>
            </Row>

            <Row className="mb-3">
              <Form.Group>
                <Form.Label>Domain SID</Form.Label>
                <Form.Control type="text" aria-describedby="sidHelpBlock" value={sid} onChange={handleSidChange} />
                <Form.Text id="sidHelpBlock" muted>
                  Place any SID from the domain here. This is required to find the domain RID
                </Form.Text>
              </Form.Group></Row>

          </Form.Group>

          <Row className="mb-3">
            <Button id="convert" className="btn btn-primary" onClick={convertSddl}>Decode</Button>
          </Row>

          {lastError === null ? null :
            <Row className="mb-3"><Alert variant="danger">{lastError}</Alert></Row>}

          {json === null ? null :
            <Form.Group>
              {label_and_text("Flags", flags)}
              {label_and_text("Owner", owner)}
              {label_and_text("Group", group)}
              <Tabs
                id="uncontrolled-tab-example"
                className="mb-3"
              >
                <Tab eventKey="dacl" title="DACL">
                  {acl_list(dacl)}
                </Tab>
                <Tab eventKey="sacl" title="SACL">
                  {acl_list(sacl)}
                </Tab>
              </Tabs>


            </Form.Group>
          }
        </Form>
      </div>
    </>
  )
}

export default App
