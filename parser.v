//on the start of each message, the first bits shall be output from seq_num.

module parser (//most recent bits are placed at the bottom of the register.
  input  wire        clk,
  input  wire        valid_in,
  input  wire [63:0] data,
  output reg  [63:0] msg_data0,
  output reg  [63:0] msg_data1,
  output reg  [63:0] seq_num,
  output reg         valid0 = 1'b1     
);

reg [15:0] clock_count = 16'd0;
reg [15:0] msg_count   = 16'd0;
reg [15:0] msg_length  = 16'd0;
reg [7:0]  len_hi      = 8'd0;          
reg [63:0] mask, head;                  
reg [15:0] h;

// clock_count: 0 = w0, 1 = w1, 2 = w2, 3 = payload,
//              4 = next word starts with the length field (msg_length was 8)
//              5 = next word starts with 2nd length byte   (msg_length was 7)

always @(posedge clk) begin
if(valid_in) begin

if(clock_count == 0) begin
clock_count <= clock_count + 1'b1;
msg_data0 <= 64'hx;                     
msg_data1 <= 64'hx;
end

if(clock_count == 1) begin
clock_count <= clock_count + 1'b1;      
seq_num[47:0] <= data[63:16];
end

if(clock_count == 2) begin
clock_count <= clock_count + 1'b1;
seq_num[63:48] <= data[15:0];
msg_count <= data[31:16]; //Message count
msg_length[15:0] <= data[47:32] - 16'd2; // FIX: 2 payload bytes are taken from this word
msg_data0[15:0] <= data[63:48];
msg_data0[63:16] <= 48'hx;
end


if(clock_count == 4) begin
msg_length <= data[63:48] - 16'd6;
if(valid0) begin msg_data0 <= {16'h0, data[47:0]}; msg_data1 <= 64'hx; end
else       begin msg_data1 <= {16'h0, data[47:0]}; msg_data0 <= 64'hx; end
clock_count <= 16'd3;
end


if(clock_count == 5) begin
msg_length <= {len_hi, data[63:56]} - 16'd7;
if(valid0) begin msg_data0 <= {8'h0, data[55:0]}; msg_data1 <= 64'hx; end
else       begin msg_data1 <= {8'h0, data[55:0]}; msg_data0 <= 64'hx; end
clock_count <= 16'd3;
end


if(clock_count == 3) begin               
if(msg_length > 16'd8) begin


//outputting data, decrementing/incrementing necessary registers.
if(valid0)begin
msg_data0 <= data;
msg_data1 <= 64'hx;
end
if(!valid0)begin
msg_data1 <= data;
msg_data0 <= 64'hx;

end
msg_length <= msg_length - 16'd8;




end else if(msg_length <= 16'd8 && msg_count > 0)begin //reset routine for each message


seq_num <= seq_num + 64'd1;              
//resetting necessary registers, incrementing valid0 register so that it is determined which output is being used, write seperate data to each different register using the number of bytes leftover.

mask = ~(64'hFFFF_FFFF_FFFF_FFFF >> (8*msg_length)); 
h    = 16'd6 - msg_length;             
head = 64'hx;
if(msg_length <= 6 && h != 0) head = data & ((64'd1 << (8*h)) - 64'd1);

if(msg_count == 1) begin                
clock_count <= 16'd0;
msg_length  <= 16'd0;
msg_count   <= 16'd0;
valid0      <= 1'd1;
if(valid0) begin msg_data0 <= data & mask; msg_data1 <= 64'hx; end
else       begin msg_data1 <= data & mask; msg_data0 <= 64'hx; end
end else begin
msg_count <= msg_count - 1'b1;
valid0 <= valid0 + 1'b1;

if(valid0 == 0)begin
msg_data1 <= data & mask;                
msg_data0 <= head;                       
end
if(valid0 == 1)begin
msg_data0 <= data & mask;
msg_data1 <= head;
end

if(msg_length == 8)begin
clock_count <= 16'd4;
end else if(msg_length == 7)begin
len_hi <= data[7:0];                    
clock_count <= 16'd5;
end else begin
msg_length <= data[63-8*msg_length -: 16] - h; 
end
end

end

end

end
end                                     

endmodule