//@ sm_output(output1)


//@ sm_entry
pub fn entry(data : &[u8]) -> ResultMessage {
    authentic_execution::debug("entry");


    output1(&33u16.to_le_bytes());

    authentic_execution::success(None)
}
